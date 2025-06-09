.. SPDX-License-Identifier: CC-BY-4.0

UEFI Secure Boot
================

UEFI Secure Boot is a verification mechanism, intended to ensure that only
code trusted by the platform can run.  This is to prevent malicious code from
hijacking the system.  Secure Boot requires that all privileged code be
signed, and that there is a trust relationship with the platform; i.e. code
which is not signed by a key enrolled in platform must not run privileged.

Within the Xen architecture, Xen, the :term:`control domain` and
:term:`hardware domain` share responsibility for running and administering the
platform.  This makes their kernels privileged as far as Secure Boot is
concerned.

When Secure Boot is active in the platform, privileged code is required to not
run any untrusted code (i.e. not run any code for which there is not a good
signature), and is required not to allow this restriction to be bypassed
(e.g. by command line request).


Support in Xen
--------------

There are multiple ways to achieve this security goal, with differing
tradeoffs for the eventual system.

On one end of the spectrum is the Unified Kernel Image.  e.g. Xen is bundled
with the dom0 kernel and init-ramdisk, with an embedded command line, and with
livepatching and kexec compiled out, and suitably signed.  The signature is
checked by the bootloader and, as this covers all the privileged code, Xen
doesn't need to perform further checks itself.

On the other end of the spectrum is maintaining the features of existing
deployments.  e.g. Xen needs signature checking capabilities for the dom0
kernel, livepatches and kexec kernels, and needs to allow the use of safe
command line options while disallowing unsafe ones.

It is important to remember that Xen is one piece of the larger platform,
where every piece depends on the correct functioning of all earlier pieces.  A
product supporting Secure Boot requires a holistic approach involving all
components in the system.  It is not sufficient to consider Xen in isolation.

.. TODO: Move "In Progress" tasks here as they become ready

Security Scope
--------------

Vulnerabilities impacting Secure Boot require a fixed component to be produced
and distributed, the vulnerable component to be revoked, and the revocation
distributed to platforms.

The following principles and guidelines indicate where Secure Boot differs
from more traditional security models, and the situations in which extra
remediation may be necessary.

Principles
^^^^^^^^^^

 * Privileged code shall include Xen and the kernel(s) of the control and
   hardware domain (both, if they're split).  While there is a privilege split
   here in Xen's regular security model, they are equal from Secure Boot's
   point of view.

 * Root or ADMIN in userspace is unprivileged from Secure Boot's point of
   view, and must not be able to alter the enforcement policy or load unsigned
   code even by e.g. editing a configuration file and rebooting.

Within Scope
^^^^^^^^^^^^

The following types of issue require remediation and revocation of vulnerable
binaries.

 * Any failure to apply enforcements even against traditionally-privileged
   userspace, including failure to authenticate new code to run and failure to
   handle revocations properly.

 * Any Out-of-Bounds write capable of altering the enforcement policy, or
   capable of bypassing enforcement, e.g. by corrupting the running code.

Out of Scope
^^^^^^^^^^^^

While typically a security issue in their own rights, these issues do not
constitute a Secure Boot vulnerability, and do not require special
remediation.

 * Denial of Service vulnerabilities.

 * Out-of-Bounds reads.

The Xen Security Team will endeavour to produce XSAs for all violations of
this security policy, including identifying them specifically as requiring
further remediation by downstreams.


In Progress
-----------

.. warning::

   The following work is still in progress.  It is provisional, and not
   security supported yet.


Secure Boot Advanced Targeting
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

SBAT is a recovation scheme for Secure Boot enabled components, using a
generation based scheme.  See `Shim SBAT.md
<https://github.com/rhboot/shim/blob/main/SBAT.md>`_ for full details.

Upstream Xen provides the infrastructure to embed SBAT metadata in
``xen.efi``, but does not maintain a generation number itself.  Downstreams
are expected to maintain their own generation numbers.


Lockdown Mode
^^^^^^^^^^^^^

A mode which causes the enforcement of the properties necessary to conform to
the Secure Boot specification.  Lockdown Mode is forced active when Secure
Boot is active in the platform, but may be activated independently too for
development purposes with the ``lockdown`` command line option.

TODO
^^^^

 * Command Line
 * Livepatching
 * Kexec
 * Userspace hypercalls
