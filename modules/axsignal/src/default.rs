use axtask::{current, exit};

use crate::*;

pub fn default_signal_handler(signal: Signal, ctx: &mut SignalContext) {
    match signal {
        Signal::SIGINT | Signal::SIGKILL => {
            // 杀死进程
            let curr = current();
            debug!("Received {:?}, killing process", signal);
            exit(0);
        }
        _ => {
            // 忽略信号
            debug!("Ignoring signal: {:?}", signal)
        }
    }
}

pub fn set_default_handlers(ctx: &mut SignalContext) {
    ctx.set_action(Signal::SIGKILL, SigAction {
        handler: SigHandler::Default(default_signal_handler),
        mask: SignalSet::SIGKILL,
        flags: SigFlags::empty(),
    });
    ctx.set_action(Signal::SIGINT, SigAction {
        handler: SigHandler::Default(default_signal_handler),
        mask: SignalSet::SIGINT,
        flags: SigFlags::empty(),
    });
}
