.. SPDX-License-Identifier: CC-BY-4.0

Lifecycle of a domid
====================

Overview
--------

A :term:`domid` is Xen's numeric identifier for a :term:`domain`.  In any
operational Xen system, there are one or more domains running.

Domids are 16-bit integers.  Regular domids start from 0, but there are some
special identifiers, e.g. ``DOMID_SELF``, and :term:`system domains<system
domain>`, e.g. ``DOMID_IDLE`` starting from 0x7ff0.  Therefore, a Xen system
can run a maximum of 32k domains concurrently.

.. note::

   Despite being exposed in the domid ABI, the system domains are internal to
   Xen and do not have lifecycles like regular domains.  Therefore, they are
   not discussed further in this document.

At system boot, Xen will construct one or more domains.  Kernels and
configuration for these domains must be provided by the bootloader, or at
Xen's compile time for more highly integrated solutions.

Correct functioning of the domain lifecycle involves ``xenstored``, and some
privileged entity which has bound the ``VIRQ_DOM_EXC`` global event channel.

.. note::

   While not a strict requirement for these to be the same entity, it is
   ``xenstored`` which typically has ``VIRQ_DOM_EXC`` bound.  This document is
   written assuming the common case.

Creation
--------

Within Xen, the ``domain_create()`` function is used to allocate and perform
bare minimum construction of a domain.  The :term:`control domain` accesses
this functionality via the ``DOMCTL_createdomain`` hypercall.

The final action that ``domain_create()`` performs before returning
successfully is to enter the new domain into the domlist.  This makes the
domain "visible" within Xen, allowing the new domid to be successfully
referenced by other hypercalls.

At this point, the domain exists as far as Xen is concerned, but not usefully
as a VM yet.  The toolstack performs further construction activities;
allocating vCPUs, RAM, copying in the initial executable code, etc.  Domains
are automatically created with one "pause" reference count held, meaning that
it is not eligible for scheduling.

When the toolstack has finished VM construction, it send an ``XS_INTRODUCE``
command to ``xenstored``.  This instructs ``xenstored`` to connect to the
guest's xenstore ring, and fire the ``@introduceDomain`` watch.  The firing of
this watch is the signal to all other components which care that a new VM has
appeared and is about to start running.

When the ``XS_INTRODUCE`` command returns successfully, the final action the
toolstack performs is to unpause the guest, using the ``DOMCTL_unpausedomain``
hypercall.  This drops the "pause" reference the domain was originally created
with, meaning that the vCPU(s) are eligible for scheduling and the domain will
start executing its first instruction.

.. note::

   It is common for vCPUs other than 0 to be left in an offline state, to be
   started by actions within the VM.

Termination
-----------

The VM runs for a period of time, but eventually stops.  It can stop for a
number of reasons, including:

 * Directly at the guest kernel's request, via the ``SCHEDOP_shutdown``
   hypercall.  The hypercall also includes the reason for the shutdown,
   e.g. ``poweroff``, ``reboot`` or ``crash``.

 * Indirectly from certain states.  E.g. executing a ``HLT`` instruction with
   interrupts disabled is interpreted as a shutdown request as it is a common
   code pattern for fatal error handling when no better options are available.

 * Indirectly from fatal exceptions.  In some states, execution is unable to
   continue, e.g. Triple Fault on x86.

 * Directly from the device model, via the ``DMOP_remote_shutdown`` hypercall.
   E.g. On x86, the 0xcf9 IO port is commonly used to perform platform
   poweroff, reset or sleep transitions.

 * Directly from the toolstack.  The toolstack is capable of initiating
   cleanup directly, e.g. ``xl destroy``.  This is typically an administration
   action of last resort to clean up a domain which malfunctioned but not
   terminated properly.

 * Directly from Xen.  Some error handling ends up using ``domain_crash()``
   when Xen doesn't think it can safely continue running the VM.

Whatever the reason for termination, Xen ends up calling ``domain_shutdown()``
to set the shutdown reason and deschedule all vCPUs.  Xen also fires the
``VIRQ_DOM_EXC`` event channel, which is a signal to ``xenstored``.

Upon receiving ``VIRQ_DOM_EXC``, ``xenstored`` re-scans all domains using the
``SYSCTL_getdomaininfolist`` hypercall.  If any domain has changed state from
running to shut down, ``xenstored`` fires the ``@releaseDomain`` watch.  The
firing of this watch is the signal to all other components which care that a
VM has stopped.

.. note::

   Xen does not treat reboot differently to poweroff; both statuses are
   forwarded to the toolstack.  It is up to the toolstack to restart the VM,
   which is typically done by constructing a new domain.

.. note::

   Some shutdowns may not result in the cleanup of a domain.  ``suspend`` for
   example can be used for snapshotting, and the VM resumes execution in the
   same domain/domid.  Therefore, a domain can cycle several times between
   running and "shut down" before moving into the destruction phase.

Destruction
-----------

The domain object in Xen is reference counted, and survives until all
references are dropped.

The ``@releaseDomain`` watch is to inform all entities that hold a reference
on the domain to clean up.  This may include:

 * Paravirtual driver backends having a grant map of the shared ring with the
   frontend.
 * A device model with a map of the IOREQ page(s).

The toolstack also has work to do in response to ``@releaseDomain``.  It must
issue the ``DOMCTL_destroydomain`` hypercall.  This hypercall can take minutes
of wall-clock time to complete for large domains as, amongst other things, it
is freeing the domain's RAM back to the system.

The actions triggered by the ``@releaseDomain`` watch are asynchronous.  There
is no guarantee as to the order in which actions start, or which action is the
final one to complete.  However, the toolstack can achieve some ordering by
delaying the ``DOMCTL_destroydomain`` hypercall if necessary.

Freeing
-------

When the final reference on the domain object is dropped, Xen will remove the
domain from the domlist.  This means the domid is no longer visible in Xen,
and no longer able to be referenced by other hypercalls.

Xen then schedules the object for deletion at some point after any concurrent
hypercalls referencing the domain have completed.

When the object is finally cleaned up, Xen fires the ``VIRQ_DOM_EXC`` event
channel again, causing ``xenstored`` to rescan an notice that the domain has
ceased to exist.  It fires the ``@releaseDomain`` watch a second time to
signal to any components which care that the domain has gone away.

E.g. The second ``@releaseDomain`` is commonly used by paravirtual driver
backends to shut themselves down.

At this point, the toolstack can reuse the domid for a new domain.
