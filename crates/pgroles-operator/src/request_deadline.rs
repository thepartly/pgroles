//! One deadline for a whole Kubernetes API request, response body included.
//!
//! kube's read and write timeouts are idle timeouts: each resets whenever a
//! byte moves, so a response that trickles in never trips them. A reconcile
//! waiting on such a response holds its controller's reconcile slot for as
//! long as the trickle lasts. This layer fixes the deadline when the request
//! is sent and enforces it on the response headers and on every read of the
//! body, whatever arrives in between.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body::{Body, Frame, SizeHint};
use tokio::time::{Instant, Sleep, sleep_until};
use tower::{BoxError, Layer, Service};

/// The request did not complete, body included, within its deadline.
#[derive(Debug, thiserror::Error)]
#[error("Kubernetes API request did not complete within {0:?}")]
pub struct DeadlineElapsed(pub Duration);

#[derive(Debug, Clone, Copy)]
pub struct RequestDeadlineLayer {
    timeout: Duration,
}

impl RequestDeadlineLayer {
    pub fn new(timeout: Duration) -> Self {
        Self { timeout }
    }
}

impl<S> Layer<S> for RequestDeadlineLayer {
    type Service = RequestDeadline<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RequestDeadline {
            inner,
            timeout: self.timeout,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RequestDeadline<S> {
    inner: S,
    timeout: Duration,
}

impl<S, Request, B> Service<Request> for RequestDeadline<S>
where
    S: Service<Request, Response = http::Response<B>>,
    S::Error: Into<BoxError>,
    S::Future: Send + 'static,
    B: Body<Data = Bytes> + Unpin,
    B::Error: Into<BoxError>,
{
    type Response = http::Response<DeadlineBody<B>>;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, BoxError>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, request: Request) -> Self::Future {
        let timeout = self.timeout;
        let deadline = Instant::now() + timeout;
        let response = self.inner.call(request);
        Box::pin(async move {
            let response = tokio::time::timeout_at(deadline, response)
                .await
                .map_err(|_| DeadlineElapsed(timeout))?
                .map_err(Into::into)?;
            Ok(response.map(|inner| DeadlineBody {
                inner,
                deadline: Box::pin(sleep_until(deadline)),
                timeout,
            }))
        })
    }
}

/// A response body that fails once its request's deadline has passed.
pub struct DeadlineBody<B> {
    inner: B,
    deadline: Pin<Box<Sleep>>,
    timeout: Duration,
}

impl<B> Body for DeadlineBody<B>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: Into<BoxError>,
{
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        let this = &mut *self;
        // The deadline first: a body that always has a byte ready must still
        // stop when its time is up.
        if this.deadline.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Some(Err(DeadlineElapsed(this.timeout).into())));
        }
        Pin::new(&mut this.inner)
            .poll_frame(cx)
            .map(|frame| frame.map(|result| result.map_err(Into::into)))
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}
