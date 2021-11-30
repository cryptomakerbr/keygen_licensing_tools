class ValidationError(Exception):
    def __init__(self, message, error_code, timestamp=None):
        super().__init__(message)
        self.error_code = error_code
        self.timestamp = timestamp
