.. SPDX-License-Identifier: CC-BY-4.0

FRED: Flexible Return and Event Delivery
========================================

Overview
--------

FRED was originally intended to improve performance (reading and parsing the
IDT, GDT/LDT and possibly the TSS is a bottleneck) and to provide an
extensible mechanism to overcome other limitations in the future (e.g. support
for more than 256 interrupt vectors).  During development, FRED was adjusted
substantially to also fix lots of technical debt that had accumulated in the
x86 architecture for the past 40 years, most of which is a fertile source of
crashes and privilege escalation bugs.

FRED is primarily concerned with establishing a new context when an event is
recognised, and restoring the old context when the event is handled.  This
includes events previously delivered through the IDT (exceptions and
interrupts), as well as ``SYSCALL`` and ``SYSENTER`` instructions which
avoided the IDT in the past for performance reasons.

FRED strives to achieve that event delivery always establishes a good CPL0
stack (and shadow stack if CET is active), that doesn't clobber still-active
state from an outer nested context, and with the CPL0 GSBASE.

Technical details
-----------------

When FRED is active, Rings 1 and 2 cannot be entered at all, Ring0
compatibility mode cant be entered (i.e. Ring0 is strictly 64bit), and
``IRET`` can no longer change privilege.  Call Gates no longer exist.

A single entrypoint is registered in ``MSR_FRED_CONFIG``.  Entries from Ring3
start at this address, while entries from Ring0 start at +256.  All
interrupts, exceptions and syscalls route these.  VMExits do not, and retain
their prior behaviour.

There are 4 Stack Levels, SL 0 thru 3 and a notion of Current Stack Level,
replacing the prior IST mechanism.  All stack pointers, and shadow stack
pointers when CET-SS is active, are registered in ``MSR_{R,S}SP_SL{0..3}``.
Supervisor Shadow Stack tokens no longer exist, and are replaced with an
alternative mechanism.

The IDT is no longer used.  The TSS is no longer used used to hold stack
pointers, nor ``MSR_ISST`` if CET Shadow Stacks are active.  ``MSR_{L,C}STAR``
as well as all SYSENTER MSRs are no longer used.  Under FRED, ``MSR_STAR`` and
``MSR_FMASK`` are used with their previous behaviour extended to all event
deliveries, not just syscalls.

The instructions ``SWAPGS``, ``CLRSSBSY``, ``SETSSBSY``, ``SYSEXIT`` and
``SYSRET`` unconditionally ``#UD``.  Establishing an initial SSP should use
``RSTORSSP``.  GS maintenance can use the new ``LKGS`` instruction.

Implementation considerations
-----------------------------

PV32 guests
"""""""""""

FRED formally removes the ability to use Rings 1 and 2, which prohibits the
use of PV32 guests.  PV32 guests are already disabled by default in the
presence of CET owing to the difficulty of using Ring 1 with CET active.
Compatibility for PV32 guests is provided by PVShim, which takes care not to
use CET in order to be able to run PV32 guests.  FRED can use the same
approach.

Initialisation
""""""""""""""

Exception handling is initialised right at the beginning of ``__start_xen()``
prior to parsing the command line.  Having exception cover this early is
important and wants to remain.

The determination of whether to use FRED or not needs to account for the
``fred`` and ``pvshim`` command line options, the ``FRED`` and ``LKGS`` CPUID
bits.

Therefore for simplicity, early exception handling will still use IDT
delivery, and later setup can switch to FRED instead.

cpu_user_regs vs vm86 segments
""""""""""""""""""""""""""""""

``struct cpu_user_regs`` exists in the public interface, and is embedded
inside ``struct vcpu_guest_context``.  From an ABI perspective, the layout
needs to remain.  ``struct cpu_user_regs`` is also a common name in Xen,
covering the event information (pushed by hardware and software) and the GPRs
(pushed by software).  From an API perspective, the name needs to remain.

The data selectors (ds, es, fs, gs) are a vestigial remnant of vm86 mode.
Hardware did push them on exit from vm86 mode, and ``IRET`` would consume them
on the way back in.

However, vm86 mode isn't usable in Long mode, and these selectors oughtn't to
have survived into the PV64 ABI.  Under FRED, hardware pushes different
information here, which needs accounting for in Xen's view of ``struct
cpu_user_regs``.

Therefore, the only option is to have the public API provide a struct by a
different name, and provide a compatibility define for the ``!__XEN__`` case,
freeing us up to have a similar but not identical ``struct cpu_user_regs``
which Xen operates on.

There are several uses of the vm86 fields in Xen:

 #. ``struct vcpu`` embeds a ``struct cpu_user_regs`` to hold GPRs/etc when
    the vCPU is scheduled out.  The vm86 fields are used by the PV logic only
    (``{save,load}_segments()``) and can be moved into separate fields in
    ``struct pv_vcpu``.  PV's ``dom0_construct()`` sets these fields directly,
    and needs a matching adjustment.

 #. As part of ``arch_{get,set}_info_guest()`` during hypercalls.  The
    guest side needs to remain as-is, but the Xen side can rearranged to use
    the new fields from above.

 #. As part of vCPU diagnostics (``show_registers()`` etc).  The ``#DF`` path
    uses the fields as scratch storage for the current register values, while
    the other diagnostics are simply accessing the state of a scheduled-out
    vCPU.

 #. In HVM's ``hvm_sanitize_regs_fields()``, to poison the fields and make
    them more obvious if used anywhere in HVM context.  This can simply be
    deleted.

 #. In x86_emulate.c's ``put_fpu()``.  As far as I can tell, this is
    completely buggy; the values will be poisoned for HVM guests, and stale
    from the prior context switch for PV guests.

Stack layout
""""""""""""

Xen's CPU stacks are 8-page (8-page aligned), arranged as::

  7 - Primary stack (with a struct cpu_info at the top)
  6 - Primary stack
  5 - Primary Shadow Stack (read-only)
  4 - #DF IST stack
  3 - #DB IST stack
  2 - NMI IST stack
  1 - #MC IST stack
  0 - IST Shadow Stacks (4x 1k, read-only)

which needs mapping into FREDs Stack Levels.

FRED Stack Levels replace IST.  Most events from Ring3 enter Ring0 at SL0,
including interrupts, and even exceptions with a non-zero Stack Level
configured.  Nested exceptions originate from Ring0 even if they were trying
to push a Ring3 event frame onto the stack, so do follow the Ring0 CSL rules.

Within Ring0, a stack switch occurs on event delivery if the event has a
higher configured Stack Level (exceptions in ``MSR_FRED_STK_LVLS``, interrupts
in ``MSR_FRED_CONFIG``).  Otherwise, the new event is delivered on the current
stack.

Under FRED, most sources of ``#DF`` are gone; failure to push a new event
frame onto a stack is the main remaining one, so ``#DF`` needs to be the
highest stack level (SL3) to catch errors at all other stack levels.

Also, FRED removes the "syscall gap", removing the primary need for ``NMI``,
``#DB`` and ``#MC`` to need separate stacks.

Therefore, Xen has no need for SL1 or SL2.  Under IDT delivery, we poison the
unused stack pointers with a non-canonical address, but we cannot do that
under FRED; they're held in MSRs and checked at WRMSR time.  Instead, we can
point the SL pairs (RSP + SSP) at each others (regular and shadow stack) guard
pages such that any use of an unused SL will escalate to ``#DF``.

FRED event delivery also realigns the stack to a 64-byte boundary (increased
from 16-byte in 64bit IDT delivery), which has an effect on the layout of
``struct cpu_info``.  By coincidence, the top-of-stack block is already 64
bytes before the start of the FRED-adjusted ``struct cpu_user_regs``, so no
changes beyond a stricter alignment check are needed right now.

In principle we could disconnect ``struct cpu_user_regs`` from ``struct
cpu_info``.  Some future extensions to FRED might even require it.  However,
right now, ``SPEC_CTRL_COND_VERW`` on exit to guest needs to access
``CPUINFO_scf`` and ``CPUINFO_verw_sel`` as absolute displacements from
``%rsp``.  This is easiest to achieve if ``struct cpu_user_regs`` is fixed and
compatible with both IDT and FRED delivery.


Still TBD
---------

Issues/areas I'm aware of, but haven't got a firm plan yet.

Call Gates
""""""""""

FRED removes Call Gates, yielding ``#GP[sel]`` instead.  This is how we
emulate call gates for PV32, but emulation is genuinely only wired up for PV32
guests, not for PV64.

PV64 guests do seem to be able to write Call Gates into their LDT/GDT, but
have the DPL 0'd in common with PV32.  Given the absence of emulation, I think
PV64 can't actually use Call Gates, but given the existing logic this also
seems to be by accident rather than design.

GS handling
"""""""""""

Xen does not use GS as a per-cpu pointer, but FRED is tied to the common OS
usage.  Therefore, when FRED is active, ``v->arch.pv.gs_base_{user,kernel}``
are logically the opposite way around when running in Xen context.

Furthermore we cannot use ``SWAPGS`` as part of context switching, and there's
no ``wrgsshadow`` instruction.  All guest GS handling within Xen needs to be
altered.

Kexec
"""""

NMI shootdown for kexec plays with IST settings carefully to keep the
non-kexecing CPUs safely contained.  This will need changing completely.
