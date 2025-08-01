#
# Series 2.
#

-doc_begin="The compiler implementation guarantees that the unreachable code is removed.
Constant expressions and unreachable branches of if and switch statements are expected."
-config=MC3A2.R2.1,+reports={safe,"first_area(^.*has an invariantly.*$)"}
-config=MC3A2.R2.1,+reports={safe,"first_area(^.*incompatible with labeled statement$)"}
-doc_end

-doc_begin="Some functions are intended to be not referenced."
-config=MC3A2.R2.1,+reports={deliberate,"first_area(^.*is never referenced$)"}
-doc_end

-doc_begin="Unreachability caused by calls to the following functions or macros is deliberate and there is no risk of code being unexpectedly left out."
-config=MC3A2.R2.1,statements+={deliberate,"macro(name(BUG||assert_failed))"}
-config=MC3A2.R2.1,statements+={deliberate, "call(decl(name(__builtin_unreachable||panic||do_unexpected_trap||machine_halt||machine_restart||reboot_or_halt)))"}
-doc_end

-doc_begin="Unreachability inside an ASSERT_UNREACHABLE() and analogous macro calls is deliberate and safe."
-config=MC3A2.R2.1,reports+={deliberate, "any_area(any_loc(any_exp(macro(name(ASSERT_UNREACHABLE||PARSE_ERR_RET||PARSE_ERR||FAIL_MSR||FAIL_CPUID)))))"}
-doc_end

-doc_begin="The asm-offset files are not linked deliberately, since they are used to generate definitions for asm modules."
-file_tag+={asm_offsets, "^xen/arch/(arm|x86)/(arm32|arm64|x86_64)/asm-offsets\\.c$"}
-config=MC3A2.R2.1,reports+={deliberate, "any_area(any_loc(file(asm_offsets)))"}
-doc_end

-doc_begin="Pure declarations (i.e., declarations without initialization) are
not executable, and therefore it is safe for them to be unreachable."
-config=MC3A2.R2.1,ignored_stmts+={"any()", "pure_decl()"}
-doc_end

-doc_begin="The following autogenerated file is not linked deliberately."
-file_tag+={C_runtime_failures,"^automation/eclair_analysis/C-runtime-failures\\.rst\\.c$"}
-config=MC3A2.R2.1,reports+={deliberate, "any_area(any_loc(file(C_runtime_failures)))"}
-doc_end

-doc_begin="Proving compliance with respect to Rule 2.2 is generally impossible:
see https://arxiv.org/abs/2212.13933 for details. Moreover, peer review gives us
confidence that no evidence of errors in the program's logic has been missed due
to undetected violations of Rule 2.2, if any. Testing on time behavior gives us
confidence on the fact that, should the program contain dead code that is not
removed by the compiler, the resulting slowdown is negligible."
-config=MC3A2.R2.2,reports+={disapplied,"any()"}
-doc_end

-doc_begin="Some labels are unused in certain build configurations, or are deliberately marked as unused, so that the compiler is entitled to remove them."
-config=MC3A2.R2.6,reports+={deliberate, "any_area(text(^.*__maybe_unused.*$))"}
-doc_end

#
# Series 3.
#

-doc_begin="Comments starting with '/*' and containing hyperlinks are safe as
they are not instances of commented-out code."
-config=MC3A2.R3.1,reports+={safe, "first_area(text(^.*https?://.*$))"}
-doc_end

#
# Series 4.
#

-doc_begin="The directive has been accepted only for the ARM codebase."
-config=MC3A2.D4.3,reports+={disapplied,"!(any_area(any_loc(file(^xen/arch/arm/arm64/.*$))))"}
-doc_end

-doc_begin="The inline asm in 'arm64/lib/bitops.c' is tightly coupled with the surronding C code that acts as a wrapper, so it has been decided not to add an additional encapsulation layer."
-file_tag+={arm64_bitops, "^xen/arch/arm/arm64/lib/bitops\\.c$"}
-config=MC3A2.D4.3,reports+={deliberate, "all_area(any_loc(file(arm64_bitops)&&any_exp(macro(^(bit|test)op$))))"}
-config=MC3A2.D4.3,reports+={deliberate, "any_area(any_loc(file(arm64_bitops))&&context(name(int_clear_mask16)))"}
-doc_end

-doc_begin="Files that are intended to be included more than once (and have
a comment that says this explicitly) do not need to conform to the directive."
-config=MC3A2.D4.10,reports+={safe, "first_area(text(^/\\* This file is intended to be included multiple times\\. \\*/$, begin-4))"}
-config=MC3A2.D4.10,reports+={safe, "first_area(text(^/\\* Generated file, do not edit! \\*/$, begin-3...begin-2))"}
-doc_end

-doc_begin="Autogenerated files that do not need to conform to the directive."
-config=MC3A2.D4.10,reports+={safe, "all_area(all_loc(file(^xen/include/generated/autoconf\\.h$)))"}
-doc_end

-doc_begin="Including multiple times a .c file is safe because every function or data item
it defines would (in the common case) be already defined. Peer reviewed by the community."
-config=MC3A2.D4.10,reports+={safe, "all_area(all_loc(^.*\\.c$))"}
-doc_end

#
# Series 5.
#

-doc_begin="The project adopted the rule with an exception listed in
'docs/misra/rules.rst'"
-config=MC3A2.R5.3,reports+={safe, "any_area(any_loc(any_exp(macro(^READ_SYSREG$))&&any_exp(macro(^WRITE_SYSREG$))))"}
-config=MC3A2.R5.3,reports+={safe, "any_area(any_loc(any_exp(macro(^max(_t)?$))&&any_exp(macro(^min(_t)?$))))"}
-config=MC3A2.R5.3,reports+={safe, "any_area(any_loc(any_exp(macro(^read[bwlq]$))&&any_exp(macro(^read[bwlq]_relaxed$))))"}
-config=MC3A2.R5.3,reports+={safe, "any_area(any_loc(any_exp(macro(^per_cpu$))&&any_exp(macro(^this_cpu$))))"}
-config=MC3A2.R5.3,reports+={safe, "any_area(any_loc(any_exp(macro(^__emulate_2op$))&&any_exp(macro(^__emulate_2op_nobyte$))))"}
-config=MC3A2.R5.3,reports+={safe, "any_area(any_loc(any_exp(macro(^read_debugreg$))&&any_exp(macro(^write_debugreg$))))"}
-doc_end

-doc_begin="Macros expanding to their own identifier (e.g., \"#define x x\") are deliberate."
-config=MC3A2.R5.5,reports+={deliberate, "all_area(macro(same_id_body())||!macro(!same_id_body()))"}
-doc_end

-doc_begin="There is no clash between function like macros and not callable objects."
-config=MC3A2.R5.5,reports+={deliberate, "all_area(macro(function_like())||decl(any()))&&all_area(macro(any())||!decl(kind(function))&&!decl(__function_pointer_decls))"}
-doc_end

-doc_begin="Clashes between function names and macros are deliberate for string handling functions since some architectures may want to use their own arch-specific implementation."
-config=MC3A2.R5.5,reports+={deliberate, "all_area(all_loc(file(^xen/arch/x86/string\\.c|xen/include/xen/string\\.h|xen/lib/.*$)))"}
-doc_end

-doc_begin="In libelf, clashes between macros and function names are deliberate and needed to prevent the use of undecorated versions of memcpy, memset and memmove."
-config=MC3A2.R5.5,reports+={deliberate, "any_area(decl(kind(function))||any_loc(macro(name(memcpy||memset||memmove))))&&any_area(any_loc(file(^xen/common/libelf/libelf-private\\.h$)))"}
-doc_end

-doc_begin="The type \"ret_t\" is deliberately defined multiple times,
depending on the guest."
-config=MC3A2.R5.6,reports+={deliberate,"any_area(any_loc(text(^.*ret_t.*$)))"}
-doc_end

-doc_begin="On X86, the types \"guest_intpte_t\", \"guest_l1e_t\" and
\"guest_l2e_t\" are deliberately defined multiple times, depending on the
number of guest paging levels."
-config=MC3A2.R5.6,reports+={deliberate,"any_area(any_loc(file(^xen/arch/x86/include/asm/guest_pt\\.h$)))&&any_area(any_loc(text(^.*(guest_intpte_t|guest_l[12]e_t).*$)))"}
-doc_end

-doc_begin="The following files are imported from the gnu-efi package."
-file_tag+={adopted_r5_6,"^xen/include/efi/.*$"}
-file_tag+={adopted_r5_6,"^xen/arch/.*/include/asm/.*/efibind\\.h$"}
-config=MC3A2.R5.6,reports+={deliberate,"any_area(any_loc(file(adopted_r5_6)))"}
-doc_end

-doc_begin="The project intentionally reuses tag names in order to have identifiers matching the applicable external specifications as well as established internal conventions.
As there is little possibility for developer confusion not resulting into compilation errors, the risk of renaming outweighs the potential advantages of compliance."
-config=MC3A2.R5.7,reports+={deliberate,"any()"}
-doc_end

#
# Series 7.
#

-doc_begin="It is safe to use certain octal constants the way they are defined
in specifications, manuals, and algorithm descriptions."
-config=MC3A2.R7.1,reports+={safe, "any_area(any_loc(any_exp(text(^.*octal-ok.*$))))"}
-doc_end

-doc_begin="Violations in files that maintainers have asked to not modify in the
context of R7.2."
-file_tag+={adopted_r7_2,"^xen/include/xen/libfdt/.*$"}
-file_tag+={adopted_r7_2,"^xen/arch/x86/include/asm/x86_64/efibind.h$"}
-file_tag+={adopted_r7_2,"^xen/include/efi/efiapi\\.h$"}
-file_tag+={adopted_r7_2,"^xen/include/efi/efidef\\.h$"}
-file_tag+={adopted_r7_2,"^xen/include/efi/efiprot\\.h$"}
-file_tag+={adopted_r7_2,"^xen/arch/x86/cpu/intel\\.c$"}
-file_tag+={adopted_r7_2,"^xen/arch/x86/cpu/amd\\.c$"}
-file_tag+={adopted_r7_2,"^xen/arch/x86/cpu/common\\.c$"}
-config=MC3A2.R7.2,reports+={deliberate,"any_area(any_loc(file(adopted_r7_2)))"}
-doc_end

-doc_begin="Violations caused by __HYPERVISOR_VIRT_START are related to the
particular use of it done in xen_mk_ulong."
-config=MC3A2.R7.2,reports+={deliberate,"any_area(any_loc(macro(name(BUILD_BUG_ON))))"}
-doc_end

-doc_begin="Allow pointers of non-character type as long as the pointee is
const-qualified."
-config=MC3A2.R7.4,same_pointee=false
-doc_end

#
# Series 8.
#

-doc_begin="The type ret_t is deliberately used and defined as int or long depending on the architecture."
-config=MC3A2.R8.3,reports+={deliberate,"any_area(any_loc(text(^.*ret_t.*$)))"}
-doc_end

-doc_begin="The following files are imported from Linux and decompress.h defines a unique and documented interface towards all the (adopted) decompress functions."
-file_tag+={adopted_decompress_r8_3,"^xen/common/bunzip2\\.c$"}
-file_tag+={adopted_decompress_r8_3,"^xen/common/unlz4\\.c$"}
-file_tag+={adopted_decompress_r8_3,"^xen/common/unlzma\\.c$"}
-file_tag+={adopted_decompress_r8_3,"^xen/common/unlzo\\.c$"}
-file_tag+={adopted_decompress_r8_3,"^xen/common/unxz\\.c$"}
-file_tag+={adopted_decompress_r8_3,"^xen/common/unzstd\\.c$"}
-config=MC3A2.R8.3,reports+={deliberate,"any_area(any_loc(file(adopted_decompress_r8_3)))&&any_area(any_loc(file(^xen/include/xen/decompress\\.h$)))"}
-doc_end

-doc_begin="Parameter name \"unused\" (with an optional numeric suffix) is deliberate and makes explicit the intention of not using such parameter within the function."
-config=MC3A2.R8.3,reports+={deliberate, "any_area(^.*parameter `unused[0-9]*'.*$)"}
-doc_end

-doc_begin="The following file is imported from Linux: ignore for now."
-file_tag+={adopted_time_r8_3,"^xen/arch/x86/time\\.c$"}
-config=MC3A2.R8.3,reports+={deliberate,"any_area(any_loc(file(adopted_time_r8_3)))&&(any_area(any_loc(file(^xen/include/xen/time\\.h$)))||any_area(any_loc(file(^xen/arch/x86/include/asm/setup\\.h$))))"}
-doc_end

-doc_begin="The following file is imported from Linux: ignore for now."
-file_tag+={adopted_cpu_idle_r8_3,"^xen/arch/x86/acpi/cpu_idle\\.c$"}
-config=MC3A2.R8.3,reports+={deliberate,"any_area(any_loc(file(adopted_cpu_idle_r8_3)))&&any_area(any_loc(file(^xen/include/xen/pmstat\\.h$)))"}
-doc_end

-doc_begin="The following file is imported from Linux: ignore for now."
-file_tag+={adopted_mpparse_r8_3,"^xen/arch/x86/mpparse\\.c$"}
-config=MC3A2.R8.3,reports+={deliberate,"any_area(any_loc(file(adopted_mpparse_r8_3)))&&any_area(any_loc(file(^xen/arch/x86/include/asm/mpspec\\.h$)))"}
-doc_end

-doc_begin="The definitions present in this file are meant to generate definitions for asm modules, and are not called by C code. Therefore the absence of prior declarations is safe."
-file_tag+={asm_offsets, "^xen/arch/(arm|x86)/(arm32|arm64|x86_64)/asm-offsets\\.c$"}
-config=MC3A2.R8.4,reports+={safe, "first_area(any_loc(file(asm_offsets)))"}
-doc_end

-doc_begin="The functions defined in this file are meant to be called from gcc-generated code in a non-release build configuration.
Therefore the absence of prior declarations is safe."
-file_tag+={gcov, "^xen/common/coverage/gcov_base\\.c$"}
-config=MC3A2.R8.4,reports+={safe, "first_area(any_loc(file(gcov)))"}
-doc_end

-doc_begin="Recognize the occurrence of current_stack_pointer as a declaration."
-file_tag+={asm_defns, "^xen/arch/x86/include/asm/asm_defns\\.h$"}
-config=MC3A2.R8.4,declarations+={safe, "loc(file(asm_defns))&&^current_stack_pointer$"}
-doc_end

-doc_begin="The function apei_(read|check|clear)_mce are dead code and are excluded from non-debug builds, therefore the absence of prior declarations is safe."
-config=MC3A2.R8.4,declarations+={safe, "^apei_(read|check|clear)_mce\\(.*$"}
-doc_end

-doc_begin="asmlinkage is a marker to indicate that the function is only used to interface with asm modules."
-config=MC3A2.R8.4,declarations+={safe,"loc(text(^(?s).*asmlinkage.*$, -1..0))"}
-doc_end

-doc_begin="Given that bsearch and sort are defined with the attribute 'gnu_inline', it's deliberate not to have a prior declaration.
See Section \"6.33.1 Common Function Attributes\" of \"GCC_MANUAL\" for a full explanation of gnu_inline."
-file_tag+={bsearch_sort, "^xen/include/xen/(sort|bsearch)\\.h$"}
-config=MC3A2.R8.4,reports+={deliberate, "any_area(any_loc(file(bsearch_sort))&&decl(name(bsearch||sort)))"}
-doc_end

-doc_begin="first_valid_mfn is defined in this way because the current lack of NUMA support in Arm and PPC requires it."
-file_tag+={first_valid_mfn, "^xen/common/page_alloc\\.c$"}
-config=MC3A2.R8.4,declarations+={deliberate,"loc(file(first_valid_mfn))"}
-doc_end

-doc_begin="The following variables are compiled in multiple translation units
belonging to different executables and therefore are safe."
-config=MC3A2.R8.6,declarations+={safe, "name(current_stack_pointer||bsearch||sort)"}
-doc_end

-doc_begin="Declarations without definitions are allowed (specifically when the
definition is compiled-out or optimized-out by the compiler)"
-config=MC3A2.R8.6,reports+={deliberate, "first_area(^.*has no definition$)"}
-doc_end

-doc_begin="The search procedure for Unix linkers is well defined, see ld(1)
manual: \"The linker will search an archive only once, at the location where it
is specified on the command line. If the archive defines a symbol which was
undefined in some object which appeared before the archive on the command line,
the linker will include the appropriate file(s) from the archive\".
In Xen, thanks to the order in which file names appear in the build commands,
if arch-specific definitions are present, they get always linked in before
searching in the lib.a archive resulting from xen/lib."
-config=MC3A2.R8.6,declarations+={deliberate, "loc(file(^xen/lib/.*$))"}
-doc_end

-doc_begin="The gnu_inline attribute without static is deliberately allowed."
-config=MC3A2.R8.10,declarations+={deliberate,"property(gnu_inline)"}
-doc_end

#
# Series 9.
#

-doc_begin="Violations in files that maintainers have asked to not modify in the
context of R9.1."
-file_tag+={adopted_r9_1,"^xen/arch/arm/arm64/lib/find_next_bit\\.c$"}
-config=MC3A2.R9.1,reports+={deliberate,"any_area(any_loc(file(adopted_r9_1)))"}
-doc_end

-doc_begin="The possibility of committing mistakes by specifying an explicit
dimension is higher than omitting the dimension."
-config=MC3A2.R9.5,reports+={deliberate, "any()"}
-doc_end

#
# Series 10.
#

-doc_begin="The value-preserving conversions of integer constants are safe"
-config=MC3A2.R10.1,etypes={safe,"any()","preserved_integer_constant()"}
-config=MC3A2.R10.3,etypes={safe,"any()","preserved_integer_constant()"}
-config=MC3A2.R10.4,etypes={safe,"any()","preserved_integer_constant()||sibling(rhs,preserved_integer_constant())"}
-doc_end

-doc_begin="Shifting non-negative integers to the right is safe."
-config=MC3A2.R10.1,etypes+={safe,
  "stmt(node(binary_operator)&&operator(shr))",
  "src_expr(definitely_in(0..))"}
-doc_end

-doc_begin="Shifting non-negative integers to the left is safe if the result is
still non-negative."
-config=MC3A2.R10.1,etypes+={safe,
  "stmt(node(binary_operator)&&operator(shl)&&definitely_in(0..))",
  "src_expr(definitely_in(0..))"}
-doc_end

-doc_begin="Bitwise logical operations on non-negative integers are safe."
-config=MC3A2.R10.1,etypes+={safe,
  "stmt(node(binary_operator)&&operator(and||or||xor))",
  "src_expr(definitely_in(0..))"}
-doc_end

-doc_begin="The implicit conversion to Boolean for logical operator arguments is well known to all Xen developers to be a comparison with 0"
-config=MC3A2.R10.1,etypes+={safe, "stmt(operator(logical)||node(conditional_operator||binary_conditional_operator))", "dst_type(ebool||boolean)"}
-doc_end

-doc_begin="The macro ISOLATE_LSB encapsulates a well-known pattern to obtain
a mask where only the lowest bit set in the argument is set, if any, for unsigned
integers arguments on two's complement architectures
(all the architectures supported by Xen satisfy this requirement)."
-config=MC3A2.R10.1,reports+={safe, "any_area(any_loc(any_exp(macro(^ISOLATE_LSB$))))"}
-doc_end

-doc_begin="XEN only supports architectures where signed integers are
representend using two's complement and all the XEN developers are aware of
this."
-config=MC3A2.R10.1,etypes+={safe,
  "stmt(operator(and||or||xor||not||and_assign||or_assign||xor_assign))",
  "any()"}
-doc_end

-doc_begin="See Section \"4.5 Integers\" of \"GCC_MANUAL\", where it says that
\"Signed `>>' acts on negative numbers by sign extension. As an extension to the
C language, GCC does not use the latitude given in C99 and C11 only to treat
certain aspects of signed `<<' as undefined. However, -fsanitize=shift (and
-fsanitize=undefined) will diagnose such cases. They are also diagnosed where
constant expressions are required.\""
-config=MC3A2.R10.1,etypes+={safe,
  "stmt(operator(shl||shr||shl_assign||shr_assign))",
  "any()"}
-doc_end

-doc_begin="Unary minus operations on unsigned type(s) have a semantics (wrap around) that is well-defined by the toolchains."
-config=MC3A2.R10.1,etypes+={safe,
  "stmt(node(unary_operator)&&operator(minus))",
  "src_expr(definitely_in(0..))"}
-doc_end

#
# Series 11
#

-doc_begin="The conversion from a function pointer to unsigned long or (void *) does not lose any information, provided that the target type has enough bits to store it."
-config=MC3A2.R11.1,casts+={safe,
  "from(type(canonical(__function_pointer_types)))
   &&to(type(canonical(builtin(unsigned long)||pointer(builtin(void)))))
   &&relation(definitely_preserves_value)"
}
-doc_end

-doc_begin="The conversion from a function pointer to a boolean has a well-known semantics that do not lead to unexpected behaviour."
-config=MC3A2.R11.1,casts+={safe,
  "from(type(canonical(__function_pointer_types)))
   &&kind(pointer_to_boolean)"
}
-doc_end

-doc_begin="The conversion from a pointer to an incomplete type to unsigned long does not lose any information, provided that the target type has enough bits to store it."
-config=MC3A2.R11.2,casts+={safe,
  "from(type(any()))
   &&to(type(canonical(builtin(unsigned long))))
   &&relation(definitely_preserves_value)"
}
-doc_end

-doc_begin="Conversions to object pointers that have a pointee type with a smaller (i.e., less strict) alignment requirement are safe."
-config=MC3A2.R11.3,casts+={safe,
  "!relation(more_aligned_pointee)"
}
-doc_end

-doc_begin="Conversions from and to integral types are safe, in the assumption that the target type has enough bits to store the value.
See also Section \"4.7 Arrays and Pointers\" of \"GCC_MANUAL\""
-config=MC3A2.R11.6,casts+={safe,
    "(from(type(canonical(integral())))||to(type(canonical(integral()))))
     &&relation(definitely_preserves_value)"}
-doc_end

-doc_begin="The conversion from a pointer to a boolean has a well-known semantics that do not lead to unexpected behaviour."
-config=MC3A2.R11.6,casts+={safe,
  "from(type(canonical(__pointer_types)))
   &&kind(pointer_to_boolean)"
}
-doc_end

-doc_begin="Violations caused by container_of are due to pointer arithmetic operations
with the provided offset. The resulting pointer is then immediately cast back to its
original type, which preserves the qualifier. This use is deemed safe.
Fixing this violation would require to increase code complexity and lower readability."
-config=MC3A2.R11.8,reports+={safe,"any_area(any_loc(any_exp(macro(^container_of$))))"}
-doc_end

-doc_begin="Function __hvm_copy in xen/arch/x86/hvm/hvm.c is a double-use
function, where the parameter needs to not be const because it can be set for
write or not"
-config=MC3A2.R11.8,reports+={safe,"any_area(any_loc(text(^.*__hvm_copy.*HVMCOPY_to_guest doesn't modify.*$)))"}
-doc_end

-doc_begin="This construct is used to check if the type is scalar, and for this purpose the use of 0 as a null pointer constant is deliberate."
-config=MC3A2.R11.9,reports+={deliberate, "any_area(any_loc(any_exp(macro(^__ACCESS_ONCE$))))"
}
-doc_end

#
# Series 12
#

-doc_begin="Consider the C standard type instead of the essential type for the purposes of determining the width in bits of the operand."
-config=MC3A2.R12.2,out_of_bounds=negative_or_too_big_for_type
-doc_end

#
# Series 13
#

-doc_begin="All developers and reviewers can be safely assumed to be well aware
of the short-circuit evaluation strategy of such logical operators."
-config=MC3A2.R13.5,reports+={disapplied,"any()"}
-doc_end

-doc_begin="Macros alternative_v?call[0-9] use sizeof and typeof to check that the argument types match the corresponding parameter ones."
-config=MC3A2.R13.6,reports+={deliberate,"any_area(any_loc(any_exp(macro(^alternative_vcall[0-9]$))&&file(^xen/arch/x86/include/asm/alternative-call\\.h*$)))"}
-config=B.UNEVALEFF,reports+={deliberate,"any_area(any_loc(any_exp(macro(^alternative_v?call[0-9]$))&&file(^xen/arch/x86/include/asm/alterantive-call\\.h*$)))"}
-doc_end

-doc_begin="Anything, no matter how complicated, inside the BUILD_BUG_ON macro is subject to a compile-time evaluation without relevant side effects."
-config=MC3A2.R13.6,reports+={safe,"any_area(any_loc(any_exp(macro(name(BUILD_BUG_ON)))))"}
-config=B.UNEVALEFF,reports+={safe,"any_area(any_loc(any_exp(macro(name(BUILD_BUG_ON)))))"}
-doc_end

#
# Series 14
#

-doc_begin="The severe restrictions imposed by this rule on the use of for
statements are not balanced by the presumed facilitation of the peer review
activity."
-config=MC3A2.R14.2,reports+={disapplied,"any()"}
-doc_end

-doc_begin="The XEN team relies on the fact that invariant conditions of 'if' statements and conditional operators are deliberate"
-config=MC3A2.R14.3,statements+={deliberate, "wrapped(any(),node(if_stmt||conditional_operator||binary_conditional_operator))" }
-doc_end

-doc_begin="Switches having a 'sizeof' operator as the condition are deliberate and have limited scope."
-config=MC3A2.R14.3,statements+={deliberate, "wrapped(any(),node(switch_stmt)&&child(cond, operator(sizeof)))" }
-doc_end

-doc_begin="The use of an invariant size argument in {put,get}_unsafe_size and array_access_ok, as defined in arch/x86(_64)?/include/asm/uaccess.h is deliberate and is deemed safe."
-file_tag+={x86_uaccess, "^xen/arch/x86(_64)?/include/asm/uaccess\\.h$"}
-config=MC3A2.R14.3,reports+={deliberate, "any_area(any_loc(file(x86_uaccess)&&any_exp(macro(^(put|get)_unsafe_size$))))"}
-config=MC3A2.R14.3,reports+={deliberate, "any_area(any_loc(file(x86_uaccess)&&any_exp(macro(^array_access_ok$))))"}
-doc_end

-doc_begin="A controlling expression of 'if' and iteration statements having integer, character or pointer type has a semantics that is well-known to all Xen developers."
-config=MC3A2.R14.4,etypes+={deliberate, "any()", "src_type(integer||character)||src_expr(type(desugar(pointer(any()))))"}
-doc_end

-doc_begin="The XEN team relies on the fact that the enum is_dying has the
constant with assigned value 0 act as false and the other ones as true,
therefore have the same behavior of a boolean"
-config=MC3A2.R14.4,etypes+={deliberate, "stmt(child(cond,child(expr,ref(^<?domain>?::is_dying$))))","src_type(enum)"}
-doc_end

#
# Series 16.
#

-doc_begin="Complying with the Rule would entail a lot of code duplication in the implementation of the x86 emulator,
therefore it is deemed better to leave such files as is."
-file_tag+={x86_emulate,"^xen/arch/x86/x86_emulate/.*$"}
-file_tag+={x86_svm_emulate,"^xen/arch/x86/hvm/svm/emulate\\.c$"}
-config=MC3A2.R16.2,reports+={deliberate, "any_area(any_loc(file(x86_emulate||x86_svm_emulate)))"}
-doc_end

-doc_begin="Statements that change the control flow (i.e., break, continue, goto, return) and calls to functions that do not return the control back are \"allowed terminal statements\"."
-stmt_selector+={r16_3_allowed_terminal, "node(break_stmt||continue_stmt||goto_stmt||return_stmt)||call(property(noreturn))"}
-config=MC3A2.R16.3,terminals+={safe, "r16_3_allowed_terminal"}
-doc_end

-doc_begin="An if-else statement having both branches ending with an allowed terminal statement is itself an allowed terminal statement."
-stmt_selector+={r16_3_if, "node(if_stmt)&&(child(then,r16_3_allowed_terminal)||child(then,any_stmt(stmt,-1,r16_3_allowed_terminal)))"}
-stmt_selector+={r16_3_else, "node(if_stmt)&&(child(else,r16_3_allowed_terminal)||child(else,any_stmt(stmt,-1,r16_3_allowed_terminal)))"}
-stmt_selector+={r16_3_if_else, "r16_3_if&&r16_3_else"}
-config=MC3A2.R16.3,terminals+={safe, "r16_3_if_else"}
-doc_end

-doc_begin="An if-else statement having an always true condition and the true branch ending with an allowed terminal statement is itself an allowed terminal statement."
-stmt_selector+={r16_3_if_true, "r16_3_if&&child(cond,definitely_in(1..))"}
-config=MC3A2.R16.3,terminals+={safe, "r16_3_if_true"}
-doc_end

-doc_begin="A switch clause ending with a statement expression which, in turn, ends with an allowed terminal statement is safe."
-config=MC3A2.R16.3,terminals+={safe, "node(stmt_expr)&&child(stmt,node(compound_stmt)&&any_stmt(stmt,-1,r16_3_allowed_terminal||r16_3_if_else||r16_3_if_true))"}
-doc_end

-doc_begin="A switch clause ending with a do-while-false the body of which, in turn, ends with an allowed terminal statement is safe.
An exception to that is the macro ASSERT_UNREACHABLE() which is effective in debug build only: a switch clause ending with ASSERT_UNREACHABLE() is not considered safe."
-config=MC3A2.R16.3,terminals+={safe, "!macro(name(ASSERT_UNREACHABLE))&&node(do_stmt)&&child(cond,definitely_in(0))&&child(body,any_stmt(stmt,-1,r16_3_allowed_terminal||r16_3_if_else||r16_3_if_true))"}
-doc_end

-doc_begin="Switch clauses ending with pseudo-keyword \"fallthrough\" are
safe."
-config=MC3A2.R16.3,reports+={safe, "any_area(end_loc(any_exp(text(/fallthrough;/))))"}
-doc_end

-doc_begin="Switch clauses ending with failure method \"BUG()\" are safe."
-config=MC3A2.R16.3,reports+={safe, "any_area(end_loc(any_exp(text(/BUG\\(\\);/))))"}
-doc_end

-doc_begin="Switch clauses ending with an explicit comment indicating the fallthrough intention are safe."
-config=MC3A2.R16.3,reports+={safe, "any_area(end_loc(any_exp(text(^(?s).*/\\* [fF]all ?through\\.? \\*/.*$,0..2))))"}
-doc_end

-doc_begin="Switch statements having a controlling expression of enum type deliberately do not have a default case: gcc -Wall enables -Wswitch which warns (and breaks the build as we use -Werror) if one of the enum labels is missing from the switch."
-config=MC3A2.R16.4,reports+={deliberate,'any_area(kind(context)&&^.* has no `default.*$&&stmt(node(switch_stmt)&&child(cond,skip(__non_syntactic_paren_stmts,type(canonical(enum_underlying_type(any())))))))'}
-doc_end

-doc_begin="A switch statement with a single switch clause and no default label may be used in place of an equivalent if statement if it is considered to improve readability."
-config=MC3A2.R16.4,switch_clauses+={deliberate,"switch(1)&&default(0)"}
-doc_end

-doc_begin="A switch statement with a single switch clause and no default label may be used in place of an equivalent if statement if it is considered to improve readability."
-config=MC3A2.R16.6,switch_clauses+={deliberate, "default(0)"}
-doc_end

#
# Series 17.
#

-doc_begin="printf()-like functions are allowed to use the variadic features provided by stdarg.h."
-config=MC3A2.R17.1,reports+={deliberate,"any_area(^.*va_list.*$&&context(ancestor_or_self(^.*printk\\(.*\\)$)))"}
-config=MC3A2.R17.1,reports+={deliberate,"any_area(^.*va_list.*$&&context(ancestor_or_self(^.*printf\\(.*\\)$)))"}
-config=MC3A2.R17.1,reports+={deliberate,"any_area(^.*va_list.*$&&context(ancestor_or_self(name(panic)&&kind(function))))"}
-config=MC3A2.R17.1,reports+={deliberate,"any_area(^.*va_list.*$&&context(ancestor_or_self(name(elf_call_log_callback)&&kind(function))))"}
-config=MC3A2.R17.1,reports+={deliberate,"any_area(^.*va_list.*$&&context(ancestor_or_self(name(vprintk_common)&&kind(function))))"}
-config=MC3A2.R17.1,macros+={hide , "^va_(arg|start|copy|end)$"}
-doc_end

-doc_begin="Not using the return value of a function does not endanger safety if it coincides with an actual argument."
-config=MC3A2.R17.7,calls+={safe, "any()", "decl(name(__builtin_memcpy||__builtin_memmove||__builtin_memset||cpumask_check))"}
-doc_end

#
# Series 18.
#

-doc_begin="Subtractions between pointers involving at least one of the linker symbols specified by the regex below
are guaranteed not to be exploited by a compiler that relies on the absence of
C99 Undefined Behaviour 45: Pointers that do not point into, or just beyond, the same array object are subtracted (6.5.6)."
-eval_file=linker_symbols.ecl
-config=MC3A2.R18.2,reports+={safe, "any_area(stmt(operator(sub)&&child(lhs||rhs, skip(__non_syntactic_paren_stmts, ref(linker_symbols)))))"}
-doc_end

-doc_begin="The following macro performs a subtraction between pointers to obtain the mfn, but does not lead to undefined behaviour."
-config=MC3A2.R18.2,reports+={safe, "any_area(any_loc(any_exp(macro(^page_to_mfn$))))"}
-doc_end

-doc_begin="Flexible array members are deliberately used and XEN developers are aware of the dangers related to them:
unexpected result when the structure is given as argument to a sizeof() operator and the truncation in assignment between structures."
-config=MC3A2.R18.7,reports+={deliberate, "any()"}
-doc_end

#
# Series 20.
#

-doc_begin="Code violating Rule 20.7 is safe when macro parameters are used: (1)
as function arguments; (2) as macro arguments; (3) as array indices; (4) as lhs
in assignments; (5) as initializers, possibly designated, in initalizer lists;
(6) as the constant expression in a switch clause label."
-config=MC3A2.R20.7,expansion_context=
{safe, "context(__call_expr_arg_contexts)"},
{safe, "left_right(^[(,\\[]$,^[),\\]]$)"},
{safe, "context(skip_to(__expr_non_syntactic_contexts, stmt_child(node(array_subscript_expr), subscript)))"},
{safe, "context(skip_to(__expr_non_syntactic_contexts, stmt_child(operator(assign), lhs)))"},
{safe, "context(skip_to(__expr_non_syntactic_contexts, stmt_child(node(init_list_expr||designated_init_expr), init)))"},
{safe, "context(skip_to(__expr_non_syntactic_contexts, stmt_child(node(case_stmt), lower||upper)))"}
-doc_end

-doc_begin="Violations involving the __config_enabled macros cannot be fixed without
breaking the macro's logic; futhermore, the macro is only ever used in the context
of the IS_ENABLED or STATIC_IF/STATIC_IF_NOT macros, so it always receives a literal
0 or 1 as input, posing no risk to safety."
-config=MC3A2.R20.7,reports+={safe, "any_area(any_loc(any_exp(macro(^___config_enabled$))))"}
-doc_end

-doc_begin="Violations due to the use of macros defined in files that are
not in scope for compliance are allowed, as that is imported code."
-file_tag+={gnu_efi_include, "^xen/include/efi/.*$"}
-file_tag+={acpi_cpu_idle, "^xen/arch/x86/acpi/cpu_idle\\.c$"}
-config=MC3A2.R20.7,reports+={safe, "any_area(any_loc(file(gnu_efi_include)||any_exp(macro(^NextMemoryDescriptor$))))"}
-config=MC3A2.R20.7,reports+={safe, "any_area(any_loc(file(acpi_cpu_idle)))"}
-doc_end

-doc_begin="To avoid compromising readability, the macros alternative_(v)?call[0-9] are allowed
not to parenthesize their arguments."
-config=MC3A2.R20.7,reports+={safe, "any_area(any_loc(any_exp(macro(^alternative_(v)?call[0-9]$))))"}
-doc_end

-doc_begin="The argument 'x' of the count_args_ macro can't be parenthesized as
the rule would require, without breaking the functionality of the macro. The uses
of this macro do not lead to developer confusion, and can thus be deviated."
-config=MC3A2.R20.7,reports+={safe, "any_area(any_loc(any_exp(macro(^count_args_$))))"}
-doc_end

-doc_begin="The argument \"fn\" in macros {COMPILE,RUNTIME}_CHECK is not parenthesized
on purpose, to be able to test function-like macros. Given the specialized and limited
use of this macro, it is deemed ok to deviate them."
-config=MC3A2.R20.7,reports+={deliberate, "any_area(any_loc(any_exp(macro(^(COMPILE_CHECK|RUNTIME_CHECK)$))))"}
-doc_end

-doc_begin="Problems related to operator precedence can not occur if the expansion of the macro argument is surrounded by tokens '{', '}' and ';'."
-config=MC3A2.R20.7,expansion_context+={safe, "left_right(^[\\{;]$,^[;\\}]$)"}
-doc_end

-doc_begin="Uses of variadic macros that have one of their arguments defined as
a macro and used within the body for both ordinary parameter expansion and as an
operand to the # or ## operators have a behavior that is well-understood and
deliberate."
-config=MC3A2.R20.12,macros+={deliberate, "variadic()"}
-doc_end

-doc_begin="Uses of a macro parameter for ordinary expansion and as an operand
to the # or ## operators within the following macros are deliberate, to provide
useful diagnostic messages to the user."
-config=MC3A2.R20.12,macros+={deliberate, "name(ASSERT||BUILD_BUG_ON||BUILD_BUG_ON_ZERO||RUNTIME_CHECK)"}
-doc_end

-doc_begin="The helper macro GENERATE_CASE may use a macro parameter for ordinary
expansion and token pasting to improve readability. Only instances where this
leads to a violation of the Rule are deviated."
-file_tag+={deliberate_generate_case, "^xen/arch/arm/vcpreg\\.c$"}
-config=MC3A2.R20.12,macros+={deliberate, "name(GENERATE_CASE)&&loc(file(deliberate_generate_case))"}
-doc_end

-doc_begin="The macro DEFINE is defined and used in excluded files asm-offsets.c.
This may still cause violations if entities outside these files are referred to
in the expansion."
-config=MC3A2.R20.12,macros+={deliberate, "name(DEFINE)&&loc(file(asm_offsets))"}
-doc_end

#
# Series 21.
#

-doc_begin="or, and and xor are reserved identifiers because they constitute alternate
spellings for the corresponding operators (they are defined as macros by iso646.h).
However, Xen doesn't use standard library headers, so there is no risk of overlap."
-config=MC3A2.R21.2,reports+={safe, "any_area(stmt(ref(kind(label)&&^(or|and|xor|not)$)))"}
-doc_end

-doc_begin="Xen does not use the functions provided by the Standard Library, but
implements a set of functions that share the same names as their Standard Library equivalent.
The implementation of these functions is available in source form, so the undefined, unspecified
or implementation-defined behaviors contemplated by the C Standard do not apply.
If some undefined or unspecified behavior does arise in the implementation, it
falls under the jurisdiction of other MISRA guidelines."
-config=MC3A2.R21.6,reports+={deliberate, "any()"}
-config=MC3A2.R21.9,reports+={deliberate, "any()"}
-config=MC3A2.R21.10,reports+={deliberate, "any()"}
-doc_end

#
# General
#

-doc_begin="do-while-[01] is a well recognized loop idiom by the xen community."
-loop_idioms={do_stmt, "literal(0)||literal(1)"}
-doc_end
-doc_begin="while-[01] is a well recognized loop idiom by the xen community."
-loop_idioms+={while_stmt, "literal(0)||literal(1)"}
-doc_end

#
# Developer confusion
#

-doc="Selection for reports that are fully contained in adopted code."
-report_selector+={adopted_report,"all_area(!kind(culprit||evidence)||all_loc(all_exp(adopted||pseudo)))"}

-doc_begin="Adopted code is not meant to be read, reviewed or modified by human
programmers:no developers' confusion is not possible. In addition, adopted code
is assumed to work as is. Reports that are fully contained in adopted code are
hidden/tagged with the 'adopted' tag."
-service_selector={developer_confusion_guidelines,"^(MC3A2\\.R2\\.1|MC3A2\\.R2\\.2|MC3A2\\.R2\\.3|MC3A2\\.R2\\.4|MC3A2\\.R2\\.5|MC3A2\\.R2\\.6|MC3A2\\.R2\\.7|MC3A2\\.R4\\.1|MC3A2\\.R5\\.3|MC3A2\\.R5\\.6|MC3A2\\.R5\\.7|MC3A2\\.R5\\.8|MC3A2\\.R5\\.9|MC3A2\\.R7\\.1|MC3A2\\.R7\\.2|MC3A2\\.R7\\.3|MC3A2\\.R8\\.7|MC3A2\\.R8\\.8|MC3A2\\.R8\\.9|MC3A2\\.R8\\.11|MC3A2\\.R8\\.12|MC3A2\\.R8\\.13|MC3A2\\.R9\\.3|MC3A2\\.R9\\.4|MC3A2\\.R9\\.5|MC3A2\\.R10\\.2|MC3A2\\.R10\\.5|MC3A2\\.R10\\.6|MC3A2\\.R10\\.7|MC3A2\\.R10\\.8|MC3A2\\.R11\\.9|MC3A2\\.R12\\.1|MC3A2\\.R12\\.3|MC3A2\\.R12\\.4|MC3A2\\.R13\\.5|MC3A2\\.R14\\.1|MC3A2\\.R14\\.2|MC3A2\\.R14\\.3|MC3A2\\.R15\\.1|MC3A2\\.R15\\.2|MC3A2\\.R15\\.3|MC3A2\\.R15\\.4|MC3A2\\.R15\\.5|MC3A2\\.R15\\.6|MC3A2\\.R15\\.7|MC3A2\\.R16\\.1|MC3A2\\.R16\\.2|MC3A2\\.R16\\.3|MC3A2\\.R16\\.4|MC3A2\\.R16\\.5|MC3A2\\.R16\\.6|MC3A2\\.R16\\.7|MC3A2\\.R17\\.7|MC3A2\\.R17\\.8|MC3A2\\.R18\\.4|MC3A2\\.R18\\.5)$"
}
-config=developer_confusion_guidelines,reports+={relied,adopted_report}
-doc_end
