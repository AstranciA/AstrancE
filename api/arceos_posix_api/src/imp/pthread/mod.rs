use alloc::{boxed::Box, collections::BTreeMap, sync::Arc};
use core::cell::UnsafeCell;
use core::ffi::{c_int, c_void};

use axerrno::{LinuxError, LinuxResult};
use axtask::AxTaskRef;
use spin::RwLock;

use crate::ctypes;
use crate::imp::fd_ops::FD_TABLE; // Import FD_TABLE for namespace inheritance
use axns::AxNamespace; // Import AxNamespace for namespace inheritance
use axprocess::{Process, Thread}; // Import Process and Thread
use axsync::{Mutex, Condvar, RwLock as AxRwLock}; // Import Mutex, Condvar, RwLock
use memory_addr::VirtAddr; // Import VirtAddr for stack allocation
use core::mem::size_of; // Import size_of for mutex size check

lazy_static::lazy_static! {
    static ref TID_TO_PTHREAD: RwLock<BTreeMap<u64, ForceSendSync<ctypes::pthread_t>>> = {
        let mut map = BTreeMap::new();
        let main_task = axtask::current();
        let main_tid = main_task.id().as_u64();
        // Assuming the main task is already associated with a Process and Thread
        // This might need adjustment based on how the initial process/thread is created
        let main_thread_arc = main_task.task_ext().thread.clone(); // Get the Arc<Thread> from TaskExt
        let main_thread = Pthread {
            inner: main_task.as_task_ref().clone(),
            retval: Arc::new(Packet {
                result: UnsafeCell::new(core::ptr::null_mut()),
            }),
            thread: main_thread_arc, // Store the Arc<Thread>
            detached: false, // Main thread is typically joinable
        };
        let ptr = Box::into_raw(Box::new(main_thread)) as *mut c_void;
        map.insert(main_tid, ForceSendSync(ptr));
        RwLock::new(map)
    };
}

struct Packet<T> {
    result: UnsafeCell<T>,
}

unsafe impl<T> Send for Packet<T> {}
unsafe impl<T> Sync for Packet<T> {}

pub struct Pthread {
    inner: AxTaskRef,
    retval: Arc<Packet<*mut c_void>>,
    thread: Arc<Thread>, // Store the associated axprocess::Thread
    detached: bool, // Whether the thread is detached
    // TODO: Add fields for thread-specific data like TLS base address
}

impl Pthread {
    fn create(
        attr: *const ctypes::pthread_attr_t,
        start_routine: extern "C" fn(arg: *mut c_void) -> *mut c_void,
        arg: *mut c_void,
    ) -> LinuxResult<ctypes::pthread_t> {
        let arg_wrapper = ForceSendSync(arg);
        let current_task = axtask::current();
        let current_process = current_task.task_ext().thread.process().clone(); // Get the current process

        let my_packet: Arc<Packet<*mut c_void>> = Arc::new(Packet {
            result: UnsafeCell::new(core::ptr::null_mut()),
        });
        let their_packet = my_packet.clone();

        // Parse pthread attributes
        let mut stack_size = axconfig::USER_STACK_SIZE; // Default stack size
        let mut detached_state = false; // Default to joinable

        if !attr.is_null() {
            let attr_ref = unsafe { &*attr };
            // TODO: Parse stack size from attr_ref.__stacksize
            // TODO: Parse detached state from attr_ref.__detachstate
            // For now, using default values
        }


        // The entry point for the new thread's task
        let main = move || {
            let arg = arg_wrapper;
            // Call the user-provided start_routine
            let ret = start_routine(arg.0);
            // Store the return value
            unsafe { *their_packet.result.get() = ret };
            // The Packet Arc is dropped here when the task finishes
        };

        // Create a new axprocess::Thread within the current process
        let new_tid = axprocess::Pid::new(); // Assuming Pid has a new() method
        let new_thread_arc = current_process.new_thread(new_tid).build();

        // Create a new axtask::TaskInner for the new thread
        // The new task should share the address space and other resources with the process
        let process_data = current_process.data::<crate::imp::task::ProcessData>().unwrap(); // Get ProcessData from the current process
        let aspace = process_data.aspace.clone(); // Share the address space
        let mut uctx = axhal::arch::UspaceContext::new(0, 0, 0); // Initial context will be set by the scheduler
        let current_pwd = axfs::api::current_dir().unwrap_or_else(|_| "/".into()); // Get current directory

        // TODO: Allocate user stack based on stack_size
        // This might involve using the address space manager (axmm)
        // For now, we are not allocating a separate user stack for the thread,
        // which is incorrect for a proper pthread implementation.
        // A proper implementation would allocate a new stack within the process's address space.
        let user_stack_base = VirtAddr::from(0); // Placeholder

        // TODO: Allocate and initialize TLS area for the new thread
        let tls_area = None; // Placeholder


        let mut new_task_inner = axtask::TaskInner::new(
            main,
            format!("pthread-{}", new_tid), // Task name
            axconfig::plat::KERNEL_STACK_SIZE, // Kernel stack size
        );

        // Set the page table root to share the address space
        new_task_inner.ctx_mut().set_page_table_root(aspace.lock().page_table_root());
        // Set the user stack pointer in the initial context
        new_task_inner.ctx_mut().set_user_sp(user_stack_base.as_usize());
        // TODO: Set the thread pointer (TP) register in the initial context for TLS access
        // uctx.set_tp(...);


        // Create the Pthread struct before initializing TaskExt
        let thread_struct = Box::new(Pthread {
            inner: new_task_inner.as_task_ref().clone(), // Will be updated after spawn
            retval: my_packet,
            thread: new_thread_arc.clone(), // Store the Arc<Thread>
            detached: detached_state, // Store the detached state
            // TODO: Initialize TLS base address in Pthread struct
        });
        let pthread_ptr = Box::into_raw(thread_struct) as *mut c_void;


        // Initialize TaskExt with the new thread and pthread pointer
        new_task_inner.init_task_ext(crate::imp::task::TaskExt::new(new_thread_arc.clone(), pthread_ptr as usize, tls_area)); // Pass pthread_ptr and tls_area

        // Spawn the new task
        let task_ref = axtask::spawn_task(new_task_inner);

        // Update the inner task reference in the Pthread struct
        unsafe { (*(pthread_ptr as *mut Pthread)).inner = task_ref.clone(); }


        // Add the new thread to the global thread table
        crate::imp::task::add_thread_to_table(&thread.thread);

        TID_TO_PTHREAD.write().insert(new_tid as u64, ForceSendSync(pthread_ptr));

        Ok(pthread_ptr)
    }

    fn current_ptr() -> *mut Pthread {
        let tid = axtask::current().id().as_u64();
        match TID_TO_PTHREAD.read().get(&tid) {
            None => core::ptr::null_mut(),
            Some(ptr) => ptr.0 as *mut Pthread,
        }
    }

    fn current() -> Option<&'static Pthread> {
        unsafe { core::ptr::NonNull::new(Self::current_ptr()).map(|ptr| ptr.as_ref()) }
    }

    fn exit_current(retval: *mut c_void) -> ! {
        let thread = Self::current().expect("fail to get current thread");
        unsafe { *thread.retval.result.get() = retval };

        // If the thread is detached, its resources should be cleaned up automatically.
        // If it's joinable, resources are cleaned up by pthread_join.
        if thread.detached {
            // TODO: Implement automatic resource cleanup for detached threads
            // This might involve marking the task for later collection or
            // ensuring that dropping the Pthread struct handles cleanup.
        }

        // The TaskInner will be exited, which will eventually drop the Pthread struct
        axtask::exit(0);
    }

    fn join(ptr: ctypes::pthread_t) -> LinuxResult<*mut c_void> {
        if core::ptr::eq(ptr, Self::current_ptr() as _) {
            return Err(LinuxError::EDEADLK);
        }

        // Get the Pthread struct from the raw pointer
        // We need to temporarily take ownership to call join, but not drop it yet
        let thread_box = unsafe { Box::from_raw(ptr as *mut Pthread) };
        let thread = Arc::new(thread_box); // Create an Arc to keep it alive during join

        let tid = thread.inner.id().as_u64();

        // Check if the thread is detached
        if thread.detached {
            // Cannot join a detached thread
            return Err(LinuxError::EINVAL);
        }

        // Join the underlying axtask::TaskInner
        thread.inner.join();

        // Get the return value
        let retval = unsafe { *thread.retval.result.get() };

        // Remove the thread from the global table and drop the Pthread struct
        TID_TO_PTHREAD.write().remove(&tid);
        // The Arc<Pthread> is dropped here, which will drop the Box<Pthread>

        Ok(retval)
    }
}

/// Returns the `pthread` struct of current thread.
pub fn sys_pthread_self() -> ctypes::pthread_t {
    Pthread::current().expect("fail to get current thread") as *const Pthread as _
}

/// Create a new thread with the given entry point and argument.
///
/// If successful, it stores the pointer to the newly created `struct __pthread`
/// in `res` and returns 0.
pub unsafe fn sys_pthread_create(
    res: *mut ctypes::pthread_t,
    attr: *const ctypes::pthread_attr_t,
    start_routine: extern "C" fn(arg: *mut c_void) -> *mut c_void,
    arg: *mut c_void,
) -> c_int {
    debug!(
        "sys_pthread_create <= {:#x}, {:#x}",
        start_routine as usize, arg as usize
    );
    syscall_body!(sys_pthread_create, {
        let ptr = Pthread::create(attr, start_routine, arg)?;
        unsafe { core::ptr::write(res, ptr) };
        Ok(0)
    })
}

/// Exits the current thread. The value `retval` will be returned to the joiner.
pub fn sys_pthread_exit(retval: *mut c_void) -> ! {
    debug!("sys_pthread_exit <= {:#x}", retval as usize);
    Pthread::exit_current(retval);
}

/// Waits for the given thread to exit, and stores the return value in `retval`.
pub unsafe fn sys_pthread_join(thread: ctypes::pthread_t, retval: *mut *mut c_void) -> c_int {
    debug!("sys_pthread_join <= {:#x}", retval as usize);
    syscall_body!(sys_pthread_join, {
        let ret = Pthread::join(thread)?;
        if !retval.is_null() {
            unsafe { core::ptr::write(retval, ret) };
        }
        Ok(0)
    })
}

/// Detaches the given thread.
pub unsafe fn sys_pthread_detach(thread: ctypes::pthread_t) -> c_int {
    debug!("sys_pthread_detach <= {:#x}", thread as usize);
    syscall_body!(sys_pthread_detach, {
        let thread_ptr = thread as *mut Pthread;
        crate::utils::check_null_mut_ptr(thread_ptr)?; // Use check_null_mut_ptr from utils
        let thread_ref = unsafe { &mut *thread_ptr };
        if thread_ref.detached {
            // Already detached
            Ok(0)
        } else {
            thread_ref.detached = true;
            // TODO: If the thread has already exited, trigger cleanup now.
            Ok(0)
        }
    })
}

// Add implementations for other pthread functions here (e.g., mutex, condvar, rwlock)
// These would involve defining PthreadMutex, PthreadCond, PthreadRwLock structs
// and implementing their corresponding sys_ functions.

#[derive(Clone, Copy)]
struct ForceSendSync<T>(T);

unsafe impl<T> Send for ForceSendSync<T> {}
unsafe impl<T> Sync for ForceSendSync<T> {}
