//! The open-file limit the daemon process runs under.
//!
//! launchd hands a job 256 descriptors. A router spends two of them per connection - one to the
//! client, one to the next hop - so an ordinary browsing session exhausts the table, and the
//! exhaustion does not announce itself as a limit: `getaddrinfo` needs a descriptor of its own and
//! reports having none as `nodename nor servname provided`, which reads as an unresolvable host.

use std::io;

/// Descriptors the daemon asks for at startup.
///
/// Far below `kern.maxfilesperproc` on any macOS this runs on, and far above what one machine
/// holds open at once.
const TARGET: u64 = 16_384;

/// The open-file limits of the current process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Descriptors the process may hold.
    pub soft: u64,
    /// Ceiling the soft limit may be raised to without privilege.
    pub hard: u64,
}

/// Raises the soft limit and writes the limits the process ended up under to the log.
///
/// A failure is warned about rather than returned: the daemon serves traffic under the limit it
/// inherited, it just runs out of descriptors sooner, and the log is where that is answerable.
pub fn raise_and_report() {
    match raise() {
        Ok(Limits { soft, hard }) => {
            tracing::info!(open_files_soft = soft, open_files_hard = hard);
        }
        Err(failure) => tracing::warn!(open_files_error = %failure),
    }
}

/// Raises the soft limit towards [`TARGET`] and returns the limits the process ends up under.
///
/// A hard limit below the target caps the result, and a soft limit already covering it is left
/// alone, so the call is idempotent.
///
/// # Errors
///
/// Returns the failure of the underlying `getrlimit` or `setrlimit` call. The daemon serves traffic
/// under the inherited limit either way, so the caller reports the failure rather than stopping.
pub fn raise() -> io::Result<Limits> {
    let current = read()?;
    let Some(soft) = wanted(current) else {
        return Ok(current);
    };
    let Limits { soft: _, hard } = current;
    write(soft, hard)?;
    read()
}

/// Returns the soft limit to ask for, or `None` when the current one already covers [`TARGET`].
fn wanted(current: Limits) -> Option<u64> {
    let Limits { soft, hard } = current;
    let target = TARGET.min(hard);
    if soft >= target {
        return None;
    }
    Some(target)
}

fn read() -> io::Result<Limits> {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let libc::rlimit { rlim_cur, rlim_max } = limit;
    Ok(Limits {
        soft: rlim_cur,
        hard: rlim_max,
    })
}

fn write(soft: u64, hard: u64) -> io::Result<()> {
    let limit = libc::rlimit {
        rlim_cur: soft,
        rlim_max: hard,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const UNLIMITED: u64 = u64::MAX;

    #[test]
    fn the_limit_launchd_hands_a_job_is_raised_to_the_target() {
        let launchd = Limits {
            soft: 256,
            hard: UNLIMITED,
        };
        assert_eq!(wanted(launchd), Some(TARGET));
    }

    #[test]
    fn a_soft_limit_that_already_covers_the_target_is_left_alone() {
        for soft in [TARGET, TARGET + 1, 1_048_576] {
            let ample = Limits {
                soft,
                hard: UNLIMITED,
            };
            assert_eq!(wanted(ample), None, "soft {soft}");
        }
    }

    #[test]
    fn a_hard_limit_below_the_target_caps_the_request() {
        let capped = Limits {
            soft: 256,
            hard: 1024,
        };
        assert_eq!(wanted(capped), Some(1024));
    }

    #[test]
    fn a_soft_limit_already_at_the_hard_one_is_left_alone() {
        let pinned = Limits {
            soft: 512,
            hard: 512,
        };
        assert_eq!(wanted(pinned), None);
    }

    #[test]
    fn raising_reports_a_limit_that_covers_the_target_and_repeats_itself() {
        let raised = raise().unwrap();
        assert!(raised.soft >= TARGET.min(raised.hard), "{raised:?}");
        assert_eq!(raise().unwrap(), raised);
    }
}
