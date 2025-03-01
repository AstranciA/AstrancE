.altmacro

.macro SAVE_GP n
sd     x\n, \n*8(sp)
.endm

.macro LOAD_GP n
ld     x\n, \n*8(sp)
.endm

.section .text
.globl   __trap_entry
.globl   __restore

__trap_entry:
	csrrw sp, sscratch, sp
	addi  sp, sp, -34 * 8

# 1      x1
# 3      x3
# 5~32   x5-x32
# 2      sscratch
# 32     sstatus
# 33     sepc

# Create TrapContext struct on stack
sd    x1, 1 * 8(sp)
sd    x3, 3 * 8(sp)
.set  n, 5
.rept 27
SAVE_GP %n
.set  n, n+1
.endr

csrr t0, sstatus
csrr t1, sepc
sd   t0, 32*8(sp) # TrapContext.sstatus
sd   t1, 33*8(sp) # TrapContext.sepc

csrr t2, sscratch
sd   t2, 2*8(sp)

mv   a0, sp
call trap_handler # trap_handler(TrapContext* trap_ctx)

__restore:
# sp is now pointing to the KernelStack
	ld   t0, 32*8(sp)
	ld   t1, 33*8(sp)
	ld   t2, 2*8(sp)
	csrw sstatus, t0
	csrw sepc, t1
	csrw sscratch, t2

	ld    x1, 1 * 8(sp)
	ld    x3, 3 * 8(sp)
	.set  n, 5
	.rept 27
	LOAD_GP %n
	.set  n, n+1
	.endr

	addi sp, sp, 34 * 8

	csrrw sp, sscratch, sp

	sret
