
import re

class PasswordValidator:
    MIN_LENGTH = 8
    MAX_LENGTH = 20
    SPECIAL_CHARS = "@$!%*?&"

    @staticmethod
    def validate_password(password: str) -> dict:
        """
        Validates a password and returns a dictionary with validation status and errors
        """
        errors = []
        
        if not isinstance(password, str):
            return {"valid": False, "errors": ["Password must be a string"]}

        if len(password) < PasswordValidator.MIN_LENGTH:
            errors.append(f"Password must be at least {PasswordValidator.MIN_LENGTH} characters long")
        
        if len(password) > PasswordValidator.MAX_LENGTH:
            errors.append(f"Password must be less than {PasswordValidator.MAX_LENGTH} characters")
        
        if re.search(r"[ ]", password):
            errors.append("Password cannot contain spaces")
            
        if not re.search(r"[A-Z]", password):
            errors.append("Password must contain at least one uppercase letter")
        
        if not re.search(r"[a-z]", password):
            errors.append("Password must contain at least one lowercase letter")
        
        if not re.search(r"[0-9]", password):
            errors.append("Password must contain at least one digit")
        
        if not re.search(f"[{re.escape(PasswordValidator.SPECIAL_CHARS)}]", password):
            errors.append(f"Password must contain at least one special character: {PasswordValidator.SPECIAL_CHARS}")
        
        return {"valid": len(errors) == 0, "errors": errors}