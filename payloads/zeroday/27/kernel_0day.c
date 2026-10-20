/* TODO: fresh kernel 0day for arm64e + PAC.
 * Structure:
 *   1. leak: read a known kernel symbol, derive kernel_slide.
 *   2. PAC: re-branch with correct pointer authentication code, or
 *      overwrite the target's PAC with the computed one.
 *   3. write: arbitrary kernel write -> disable amfi/KTRR, enable shell.
 *   4. callback to C2.
 */
// extern void *kernel_slide;  // from the leak primitive
// set_task_map_root() { /* patch cred to 0,0 */ }
// enable_kernel_write() { /* patch amfi flags */ }
// install_shell_cb();