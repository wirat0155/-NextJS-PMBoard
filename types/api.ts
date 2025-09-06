export interface ApiErrorResponse {
    message: string,
    errors?: unknown;
    retryAfter?: number;
    statusCode: number;
}