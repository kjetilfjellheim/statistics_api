use actix_web::{body::MessageBody, dev::{ServiceRequest, ServiceResponse}, middleware::Next, Error};
use tracing::debug;

/**
 * Middleware for timing requests.
 */
pub async fn timing_middleware(
    request: ServiceRequest,
    next: Next<impl MessageBody>,
) -> Result<ServiceResponse<impl MessageBody>, Error> {
    let start_time = std::time::Instant::now();
    let path = &request.path().to_owned();
    let method = &request.method().to_owned();
    let response = next.call(request).await;
    let response_code = match &response {
        Ok(service_response) => service_response.status().as_u16(),
        Err(_) => 500, // If there's an error, we assume a server error
    };
    let duration = start_time.elapsed();
    debug!(target: "performance", "Request for {} {} with status {} processed in {:?}ms", method, path, response_code, duration.as_millis());
    response
}
