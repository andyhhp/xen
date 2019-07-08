.. SPDX-License-Identifier: CC-BY-4.0

Technical Debt
==============

Hypervisor
----------

CONFIG_PDX
~~~~~~~~~~

Xen uses the term MFN for Machine Frame Number, which is synonymous with
Linux's PFN, and maps linearly to system/host/machine physical addresses.

For every page of RAM, a ``struct page_info`` is needed for tracking purposes.
In the simple case, the frametable is an array of ``struct page_info[]``
indexed by MFN.

However, this is inefficient when a system has banks of RAM at spread out in
address space, as a large amount of space is wasted on frametable entries for
non-existent frames.  This wastes both virtual address space and RAM.

As a consequence, Xen has a compression scheme known as PDX which removes
unused bits out of the middle of MFNs, to make a more tightly packed Page
inDeX, which in turn reduces the size of the frametable for system.

At the moment, PDX compression is unconditionally used.

However, PDX compression does come with a cost in terms of the complexity to
convert between PFNs and pages, which is a common operation in Xen.

Typically, ARM32 systems do have RAM banks in discrete locations, and want to
use PDX compression, while typically ARM64 and x86 systems have RAM packed
from 0 with no holes.

The goal of this work is to have ``CONFIG_PDX`` selected by ARM32 only.  This
requires slightly untangling the memory management code in ARM and x86 to give
it a clean compile boundary where PDX conversions are used.


Waitqueue infrastructure
~~~~~~~~~~~~~~~~~~~~~~~~

Livepatching safety in Xen depends on all CPUs rendezvousing on the return to
guest path, with no stack frame.  The vCPU waitqueue infrastructure undermines
this safety by copying a stack frame sideways, and ``longjmp()``\-ing away.

Waitqueues are only used by the introspection/mem_event/paging infrastructure,
where the design of the rings causes some problems.  There is a single 4k page
used for the ring, which serves both synchronous requests, and lossless async
requests.  In practice, introspecting an 11-vcpu guest is sufficient to cause
the waitqueue infrastructure to start to be used.

A better design of ring would be to have a slot per vcpu for synchronous
requests (simplifies producing and consuming of requests), and a multipage
ring buffer (of negotiable size) with lossy semantics for async requests.

A design such as this would guarantee that Xen never has to block waiting for
userspace to create enough space on the ring for a vcpu to write state out.

.. note::

   There are other aspects of the existing ring infrastructure which are
   driving a redesign, but these don't relate directly to the waitqueue
   infrastructure and livepatching safety.

   The most serious problem is that the ring infrastructure is GFN based,
   which leaves the guest either able to mess with the ring, or a shattered
   host superpage where the ring used to be, and the guest balloon driver able
   to prevent the introspection agent from connecting/reconnecting the ring.

As there are multiple compelling reasons to redesign the ring infrastructure,
the plan is to introduce the new ring ABI, deprecate and remove the old ABI,
and simply delete the waitqueue infrastructure at that point, rather than try
to redesign livepatching from scratch in an attempt to cope with unwinding old
stack frames.


Dom0
----

Remove xenstored's dependencies on unstable interfaces
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Various xenstored implementations use libxc for two purposes.  It would be a
substantial advantage to move xenstored onto entirely stable interfaces, which
disconnects it from the internal of the libxc.

1. Foreign mapping of the store ring

   This is obsolete since :xen-cs:`6a2de353a9` (2012) which allocated grant
   entries instead, to allow xenstored to function as a stub-domain without dom0
   permissions.  :xen-cs:`38eeb3864d` dropped foreign mapping for cxenstored.
   However, there are no OCaml bindings for libxengnttab.

   Work Items:

   * Minimal ``tools/ocaml/libs/xg/`` binding for ``tools/libs/gnttab/``.
   * Replicate :xen-cs:`38eeb3864d` for oxenstored as well.

2. Figuring out which domain(s) have gone away

   Currently, the handling of domains is asymmetric.

   * When a domain is created, the toolstack explicitly sends an
     ``XS_INTRODUCE(domid, store mfn, store evtchn)`` message to xenstored, to
     cause xenstored to connect to the guest ring, and fire the
     ``@introduceDomain`` watch.

   * When a domain is destroyed, Xen fires ``VIRQ_DOM_EXC`` which is bound by
     xenstored, rather than the toolstack.  xenstored updates its idea of the
     status of domains, and fires the ``@releaseDomain`` watch.

     Xenstored uses ``xc_domain_getinfo()``, to work out which domain(s) have gone
     away, and only cares about the shutdown status.

     Furthermore, ``@releaseDomain`` (like ``VIRQ_DOM_EXC``) is a single-bit
     message, which requires all listeners to evaluate whether the message applies
     to them or not.  This results in a flurry of ``xc_domain_getinfo()`` calls
     from multiple entities in the system, which all serialise on the domctl lock
     in Xen.

     Work Items:

     * Figure out how shutdown status can be expressed in a stable way from Xen.
     * Figure out if ``VIRQ_DOM_EXC`` and ``@releaseDomain`` can be extended
       or superseded to carry at least a domid, to make domain shutdown scale
       better.
     * Figure out if ``VIRQ_DOM_EXC`` would better be bound by the toolstack,
       rather than xenstored.
