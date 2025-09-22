class BaseService:
    def __init__(self, db):
        self.db = db

    def _success_response(self, data):
        return True, data, None

    def _error_response(self, message):
        return False, None, message