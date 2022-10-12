open Printf
open Xenctrl

let xc = Xenctrl.interface_open ()

let str_of_x86_physinfo_cap_flag f =
  match f with
  | CAP_X86_ASSISTED_XAPIC -> "xapic"
  | CAP_X86_ASSISTED_X2APIC -> "x2apic"

let _ =
  let p = physinfo xc in

  printf "Physinfo:\n";

  printf "  threads_per_core %d\n" p.threads_per_core;

  let () = match p.arch_capabilities with
    | X86 x ->
       begin
         printf "  arch cap flags:";
         List.iter (fun x -> printf " %s" (str_of_x86_physinfo_cap_flag x)) x;
         printf "\n"
       end
    | ARM _ -> printf "Bad arch\n" in

  printf "Starting GC.compact()%!\n";
  Gc.compact ();
  printf "Done\n";
  ()
