class AnalysisIncompleteError(RuntimeError):
    def __init__(self, message, failed_checks=None):
        super().__init__(message)
        self.message = message
        self.failed_checks = tuple(failed_checks or ())
