use tracing::{metadata::LevelFilter, Subscriber};
use tracing_subscriber::{
    filter::FilterFn, prelude::__tracing_subscriber_SubscriberExt, registry::LookupSpan,
    util::SubscriberInitExt, EnvFilter, Layer,
};

/// Initialize logging
///
/// Set up a `Subscriber` with two stdout layer
pub fn init() {
    let subscriber = tracing_subscriber::registry();

    // Set global subscriber
    subscriber.with(stdout_layer()).init();
}

/// Construct a formatting layer with logging to stdout.
fn stdout_layer<S>() -> impl Layer<S>
where
    for<'span> S: Subscriber + LookupSpan<'span>,
{
    // Set default log-level to INFO if `RUST_LOG` is not set.
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(LevelFilter::INFO.to_string()));

    let span_filter = FilterFn::new(|metadata| !metadata.is_span());

    tracing_subscriber::fmt::layer()
        .with_target(true)
        .with_file(true)
        .with_line_number(true)
        .with_ansi(cfg!(debug_assertions))
        .boxed()
        .with_filter(span_filter)
        .and_then(env_filter)
}
