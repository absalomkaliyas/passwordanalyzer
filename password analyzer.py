import re
import math
import string
from collections import Counter

class PasswordStrengthAnalyzer:
    def __init__(self):
        self.common_passwords = {
            '123456', 'password', '123456789', '12345678', '12345',
            '1234567', '1234567890', 'qwerty', 'abc123', '111111',
            'password123', 'admin', 'welcome', 'letmein', 'monkey',
            'sunshine', 'iloveyou', 'starwars', 'football', 'charlie'
        }
        # Define a consistent maximum possible score for display purposes
        # Base points: 3 (length) + 4 (char types) + 2 (entropy) = 9
        # Max positive score can be 9.
        # Deductions can make it lower.
        self.max_display_score = 9 
    
    def calculate_entropy(self, password):
        """
        Calculate Shannon entropy of a password.
        This measures the actual randomness of the given password based on character frequencies.
        The result is total bits of entropy for the entire password.
        """
        if not password:
            return 0
        
        char_counts = Counter(password)
        password_length = len(password)
        
        entropy_per_char = 0
        for count in char_counts.values():
            probability = count / password_length
            entropy_per_char -= probability * math.log2(probability)
        
        return entropy_per_char * password_length # Total entropy
    
    def _check_sequences(self, password, results):
        """Helper to check for common sequential patterns."""
        feedback_added = False

        # Numeric sequences (e.g., 123, 321)
        for i in range(len(string.digits) - 2):
            seq_asc = string.digits[i:i+3]
            seq_desc = seq_asc[::-1]
            if seq_asc in password or seq_desc in password:
                results['score'] -= 1
                results['feedback'].append("Avoid sequential numbers (e.g., 123, 321)")
                feedback_added = True
                break
        
        # Alphabetic sequences (e.g., abc, cba, ABC, CBA)
        # Check both lowercase and uppercase sequences
        if not feedback_added: # Avoid double penalty if both num and alpha seq exist
            for i in range(len(string.ascii_lowercase) - 2):
                seq_asc_lower = string.ascii_lowercase[i:i+3]
                seq_desc_lower = seq_asc_lower[::-1]
                seq_asc_upper = string.ascii_uppercase[i:i+3]
                seq_desc_upper = seq_asc_upper[::-1]

                if (seq_asc_lower in password or seq_desc_lower in password or
                    seq_asc_upper in password or seq_desc_upper in password):
                    results['score'] -= 1
                    results['feedback'].append("Avoid sequential letters (e.g., abc, CBA)")
                    break

    def analyze_password(self, password):
        """
        Analyze password strength based on multiple factors.
        Returns a dictionary with analysis results.
        """
        results = {
            'password': password,
            'length': len(password),
            'score': 0,
            'strength': '',
            'feedback': []
        }
        
        # --- Length checks ---
        if len(password) >= 8:
            results['score'] += 1
        else:
            results['feedback'].append("Password should be at least 8 characters long.")
        
        if len(password) >= 12:
            results['score'] += 1
        if len(password) >= 16:
            results['score'] += 1
        
        # --- Character variety checks ---
        has_lower = bool(re.search(r'[a-z]', password))
        has_upper = bool(re.search(r'[A-Z]', password))
        has_digit = bool(re.search(r'\d', password))
        # More robust special character regex to include commonly used ones
        has_special = bool(re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>/?`~]', password))
        
        char_types = sum([has_lower, has_upper, has_digit, has_special])
        results['score'] += char_types
        
        # Provide feedback for missing character types
        if not has_lower:
            results['feedback'].append("Add lowercase letters.")
        if not has_upper:
            results['feedback'].append("Add uppercase letters.")
        if not has_digit:
            results['feedback'].append("Add numbers.")
        if not has_special:
            results['feedback'].append("Add special characters (e.g., !@#$%^&*).")
        
        # --- Common password check ---
        if password.lower() in self.common_passwords:
            results['score'] -= 2
            results['feedback'].append("Avoid common passwords.")
        
        # --- Repetitive characters check (e.g., 'aaa', '111') ---
        if re.search(r'(.)\1{2,}', password):
            results['score'] -= 1
            results['feedback'].append("Avoid repetitive characters (e.g., 'aaa', '111').")
        
        # --- Sequential characters check ---
        self._check_sequences(password, results) # Using the helper method
        
        # --- Entropy calculation and scoring ---
        entropy = self.calculate_entropy(password)
        results['entropy'] = round(entropy, 2)
        
        if entropy > 60:
            results['score'] += 2
        elif entropy > 40:
            results['score'] += 1
        
        # --- Determine strength level ---
        # Ensure score doesn't go below 0 for strength categorization
        final_score = max(0, results['score'])

        if final_score >= 8:
            results['strength'] = 'Very Strong'
        elif final_score >= 6:
            results['strength'] = 'Strong'
        elif final_score >= 4:
            results['strength'] = 'Moderate'
        elif final_score >= 2:
            results['strength'] = 'Weak'
        else:
            results['strength'] = 'Very Weak'
        
        # Add entropy feedback if very low
        if entropy < 30 and "Password entropy is low; consider more randomness." not in results['feedback']:
            results['feedback'].append("Password entropy is low; consider more randomness.")
        
        # Ensure the score does not exceed the theoretical maximum for display consistency
        results['score'] = min(final_score, self.max_display_score)

        return results
    
    def print_analysis(self, results):
        """Print formatted analysis results."""
        print(f"\nPassword Analysis Results:")
        print(f"Password: {'*' * len(results['password'])}") # Mask password for security
        print(f"Length: {results['length']} characters")
        print(f"Entropy: {results['entropy']} bits")
        # Use the consistent max_display_score here
        print(f"Strength: {results['strength']} (Score: {results['score']}/{self.max_display_score})") 
        
        if results['feedback']:
            print("\nRecommendations:")
            for feedback in results['feedback']:
                print(f"- {feedback}")
        else:
            print("\nExcellent! No improvements needed.")

def main():
    analyzer = PasswordStrengthAnalyzer()
    
    print("Password Strength Analyzer")
    print("=" * 30)
    
    while True:
        password = input("\nEnter a password to analyze (or 'quit' to exit): ")
        
        if password.lower() == 'quit':
            break
        
        # Handle empty input immediately
        if not password:
            print("Please enter a password.")
            continue
            
        results = analyzer.analyze_password(password)
        analyzer.print_analysis(results)

if __name__ == "__main__":
    main()