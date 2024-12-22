use colored::Colorize;
use std::io::Write;

pub fn setup_logger() {
    let env = env_logger::Env::default().filter_or("MY_LOG_LEVEL", "trace");
    env_logger::Builder::from_env(env)
        .format(|buf, record| {
            let common_buf = format!(
                "{} {}:{}",
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                record.module_path().unwrap(),
                record.line().unwrap()
            )
            .as_str()
            .truecolor(128, 128, 128);

            match record.level() {
                log::Level::Trace => {
                    writeln!(
                        buf,
                        "{} [{}] {}",
                        common_buf,
                        "TRACE".white(),
                        record.args()
                    )
                    .unwrap();
                    Ok(())
                }
                log::Level::Debug => {
                    writeln!(buf, "{} [{}] {}", common_buf, "DEBUG".blue(), record.args()).unwrap();
                    Ok(())
                }
                log::Level::Info => {
                    writeln!(
                        buf,
                        "{} [{}] {}",
                        common_buf,
                        "INFO ".white().bold(),
                        record.args()
                    )
                    .unwrap();
                    Ok(())
                }
                log::Level::Warn => {
                    writeln!(
                        buf,
                        "{} [{}] {}",
                        common_buf,
                        "WARN ".yellow(),
                        record.args()
                    )
                    .unwrap();
                    Ok(())
                }
                log::Level::Error => {
                    writeln!(buf, "{} [{}] {}", common_buf, "ERROR".red(), record.args()).unwrap();
                    Ok(())
                }
            }
        })
        .init();
}
