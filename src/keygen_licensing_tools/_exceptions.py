class ValidationError(Exception):
    def __init__(self, message, code, timestamp=None):
        super().__init__(message)
        self.code = code
        self.timestamp = timestamp
