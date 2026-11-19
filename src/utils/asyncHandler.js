/**
 * Wraps an async route handler/middleware so rejected promises
 * are forwarded to Express' error middleware automatically.
 */
const asyncHandler = (fn) => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);

export default asyncHandler;
