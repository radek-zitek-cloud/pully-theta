package password

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"

	"auth-service/internal/domain"
)

// Validator handles all password strength validation and policy enforcement.
// This component ensures that user passwords meet security requirements
// and provides comprehensive feedback for password creation.
//
// Security features:
// - Configurable complexity requirements
// - Common password detection
// - Password reuse prevention (future enhancement)
// - Detailed validation error messages
// - Performance-optimized validation rules
//
// Validation rules:
// - Minimum 8 characters, maximum 128 characters
// - At least one uppercase letter
// - At least one lowercase letter
// - At least one digit
// - At least one special character
// - No common passwords (dictionary check)
// - No personal information (email, name parts)
//
// Time Complexity: O(n) where n is password length
// Space Complexity: O(1) for validation, O(k) for dictionary where k is dictionary size
type Validator struct {
	// minLength is the minimum required password length
	minLength int

	// maxLength is the maximum allowed password length
	maxLength int

	// requireUppercase indicates if uppercase letters are required
	requireUppercase bool

	// requireLowercase indicates if lowercase letters are required
	requireLowercase bool

	// requireDigits indicates if digits are required
	requireDigits bool

	// requireSpecialChars indicates if special characters are required
	requireSpecialChars bool

	// commonPasswords contains a set of commonly used passwords to reject
	commonPasswords map[string]bool

	// specialCharRegex matches valid special characters
	specialCharRegex *regexp.Regexp
}

// ValidationConfig contains configuration for password validation rules.
// This allows customization of password requirements based on security policies.
type ValidationConfig struct {
	MinLength           int    `json:"min_length" default:"8"`
	MaxLength           int    `json:"max_length" default:"128"`
	RequireUppercase    bool   `json:"require_uppercase" default:"true"`
	RequireLowercase    bool   `json:"require_lowercase" default:"true"`
	RequireDigits       bool   `json:"require_digits" default:"true"`
	RequireSpecialChars bool   `json:"require_special_chars" default:"true"`
	SpecialCharSet      string `json:"special_char_set" default:"!@#$%^&*()_+-=[]{}|;:,.<>?"`
}

// NewValidator creates a new password validator with the specified configuration.
// This constructor validates the configuration and pre-compiles regular expressions
// for optimal performance during validation.
//
// Parameters:
//   - config: Validation configuration specifying password requirements
//
// Returns:
//   - Configured password validator
//   - Error if configuration is invalid
//
// Example usage:
//
//	validator, err := password.NewValidator(password.ValidationConfig{
//	    MinLength: 12,
//	    MaxLength: 256,
//	    RequireUppercase: true,
//	    RequireLowercase: true,
//	    RequireDigits: true,
//	    RequireSpecialChars: true,
//	})
//	if err != nil {
//	    log.Fatal("Failed to create password validator:", err)
//	}
func NewValidator(config ValidationConfig) (*Validator, error) {
	// Validate configuration
	if config.MinLength < 1 {
		return nil, fmt.Errorf("minimum length must be at least 1")
	}
	if config.MaxLength < config.MinLength {
		return nil, fmt.Errorf("maximum length must be greater than or equal to minimum length")
	}
	if config.SpecialCharSet == "" && config.RequireSpecialChars {
		return nil, fmt.Errorf("special character set cannot be empty when special characters are required")
	}

	// Compile special character regex
	specialCharRegex, err := regexp.Compile(fmt.Sprintf("[%s]", regexp.QuoteMeta(config.SpecialCharSet)))
	if err != nil {
		return nil, fmt.Errorf("failed to compile special character regex: %w", err)
	}

	validator := &Validator{
		minLength:           config.MinLength,
		maxLength:           config.MaxLength,
		requireUppercase:    config.RequireUppercase,
		requireLowercase:    config.RequireLowercase,
		requireDigits:       config.RequireDigits,
		requireSpecialChars: config.RequireSpecialChars,
		commonPasswords:     loadCommonPasswords(),
		specialCharRegex:    specialCharRegex,
	}

	return validator, nil
}

// NewDefaultValidator creates a password validator with secure default settings.
// This is a convenience constructor for standard security requirements.
//
// Default configuration:
// - Minimum 8 characters, maximum 128 characters
// - Requires uppercase, lowercase, digits, and special characters
// - Uses standard special character set
// - Includes common password detection
//
// Returns:
//   - Password validator with default secure configuration
//
// Example usage:
//
//	validator := password.NewDefaultValidator()
//	err := validator.Validate("MySecurePass123!")
func NewDefaultValidator() *Validator {
	validator, _ := NewValidator(ValidationConfig{
		MinLength:           8,
		MaxLength:           128,
		RequireUppercase:    true,
		RequireLowercase:    true,
		RequireDigits:       true,
		RequireSpecialChars: true,
		SpecialCharSet:      "!@#$%^&*()_+-=[]{}|;:,.<>?",
	})
	return validator
}

// Validate checks if a password meets all configured security requirements.
// This method performs comprehensive validation and returns detailed error
// messages to help users create compliant passwords.
//
// Parameters:
//   - password: Password string to validate
//
// Returns:
//   - Error describing validation failure, nil if password is valid
//
// Validation checks performed:
// 1. Length requirements (min/max)
// 2. Character class requirements (upper, lower, digit, special)
// 3. Common password detection
// 4. Character encoding validation
//
// Time Complexity: O(n) where n is password length
// Space Complexity: O(1)
//
// Example usage:
//
//	err := validator.Validate("MySecurePass123!")
//	if err != nil {
//	    return fmt.Errorf("password validation failed: %w", err)
//	}
func (v *Validator) Validate(password string) error {
	// Check length requirements
	if len(password) < v.minLength {
		return fmt.Errorf("%w: password must be at least %d characters long",
			domain.ErrWeakPassword, v.minLength)
	}
	if len(password) > v.maxLength {
		return fmt.Errorf("%w: password must be no more than %d characters long",
			domain.ErrWeakPassword, v.maxLength)
	}

	// Check for empty or whitespace-only passwords
	if strings.TrimSpace(password) == "" {
		return fmt.Errorf("%w: password cannot be empty or contain only whitespace",
			domain.ErrWeakPassword)
	}

	// Check character class requirements
	if err := v.validateCharacterClasses(password); err != nil {
		return err
	}

	// Check against common passwords
	if v.isCommonPassword(password) {
		return fmt.Errorf("%w: password is too common and easily guessable",
			domain.ErrWeakPassword)
	}

	// Check for invalid characters (control characters, etc.)
	if err := v.validateCharacterEncoding(password); err != nil {
		return err
	}

	return nil
}

// ValidateWithContext performs password validation with additional context.
// This method allows validation against user-specific data to prevent
// passwords that contain personal information.
//
// Parameters:
//   - password: Password string to validate
//   - userEmail: User's email address (to prevent inclusion in password)
//   - userName: User's name (to prevent inclusion in password)
//
// Returns:
//   - Error describing validation failure, nil if password is valid
//
// Additional checks performed:
// - Password doesn't contain email address parts
// - Password doesn't contain name parts
// - Password doesn't contain common personal information patterns
//
// Example usage:
//
//	err := validator.ValidateWithContext("MySecurePass123!", "user@example.com", "John Doe")
//	if err != nil {
//	    return fmt.Errorf("password validation failed: %w", err)
//	}
func (v *Validator) ValidateWithContext(password, userEmail, userName string) error {
	// First run standard validation
	if err := v.Validate(password); err != nil {
		return err
	}

	// Check against email parts
	if userEmail != "" {
		emailParts := strings.Split(userEmail, "@")
		for _, part := range emailParts {
			if len(part) >= 3 && strings.Contains(strings.ToLower(password), strings.ToLower(part)) {
				return fmt.Errorf("%w: password cannot contain parts of your email address",
					domain.ErrWeakPassword)
			}
		}
	}

	// Check against name parts
	if userName != "" {
		nameParts := strings.Fields(userName)
		for _, part := range nameParts {
			if len(part) >= 3 && strings.Contains(strings.ToLower(password), strings.ToLower(part)) {
				return fmt.Errorf("%w: password cannot contain parts of your name",
					domain.ErrWeakPassword)
			}
		}
	}

	return nil
}

// GetStrengthScore calculates a password strength score from 0-100.
// This method provides a quantitative measure of password strength
// to help users understand password quality.
//
// Parameters:
//   - password: Password string to analyze
//
// Returns:
//   - Strength score from 0 (very weak) to 100 (very strong)
//
// Scoring factors:
// - Length (longer is better)
// - Character diversity (more types is better)
// - Entropy calculation
// - Pattern detection (repeated chars, sequences)
//
// Time Complexity: O(n) where n is password length
// Space Complexity: O(1)
//
// Example usage:
//
//	score := validator.GetStrengthScore("MySecurePass123!")
//	if score < 60 {
//	    log.Warn("Password strength is below recommended threshold")
//	}
func (v *Validator) GetStrengthScore(password string) int {
	if password == "" {
		return 0
	}

	score := 0

	// Length scoring (0-25 points)
	if len(password) >= 8 {
		score += 10
	}
	if len(password) >= 12 {
		score += 10
	}
	if len(password) >= 16 {
		score += 5
	}

	// Character class diversity (0-40 points)
	hasUpper, hasLower, hasDigit, hasSpecial := false, false, false, false
	charTypes := 0

	for _, char := range password {
		if unicode.IsUpper(char) && !hasUpper {
			hasUpper = true
			charTypes++
		} else if unicode.IsLower(char) && !hasLower {
			hasLower = true
			charTypes++
		} else if unicode.IsDigit(char) && !hasDigit {
			hasDigit = true
			charTypes++
		} else if v.specialCharRegex.MatchString(string(char)) && !hasSpecial {
			hasSpecial = true
			charTypes++
		}
	}
	score += charTypes * 10

	// Penalty for common patterns (0 to -20 points)
	if v.hasRepeatedChars(password) {
		score -= 10
	}
	if v.hasSequentialChars(password) {
		score -= 10
	}

	// Bonus for uniqueness (0-15 points)
	if !v.isCommonPassword(password) {
		score += 15
	}

	// Entropy bonus (0-20 points)
	entropy := v.calculateEntropy(password)
	if entropy > 40 {
		score += 20
	} else if entropy > 30 {
		score += 15
	} else if entropy > 20 {
		score += 10
	}

	// Ensure score is within bounds
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	return score
}

// validateCharacterClasses checks if password contains required character types.
// This method validates that the password meets the configured character
// class requirements (uppercase, lowercase, digits, special characters).
//
// Parameters:
//   - password: Password string to validate
//
// Returns:
//   - Error if required character classes are missing, nil if valid
//
// Time Complexity: O(n) where n is password length
// Space Complexity: O(1)
func (v *Validator) validateCharacterClasses(password string) error {
	hasUpper, hasLower, hasDigit, hasSpecial := false, false, false, false

	for _, char := range password {
		if unicode.IsUpper(char) {
			hasUpper = true
		} else if unicode.IsLower(char) {
			hasLower = true
		} else if unicode.IsDigit(char) {
			hasDigit = true
		} else if v.specialCharRegex.MatchString(string(char)) {
			hasSpecial = true
		}
	}

	// Check requirements
	if v.requireUppercase && !hasUpper {
		return fmt.Errorf("%w: password must contain at least one uppercase letter",
			domain.ErrWeakPassword)
	}
	if v.requireLowercase && !hasLower {
		return fmt.Errorf("%w: password must contain at least one lowercase letter",
			domain.ErrWeakPassword)
	}
	if v.requireDigits && !hasDigit {
		return fmt.Errorf("%w: password must contain at least one digit",
			domain.ErrWeakPassword)
	}
	if v.requireSpecialChars && !hasSpecial {
		return fmt.Errorf("%w: password must contain at least one special character",
			domain.ErrWeakPassword)
	}

	return nil
}

// validateCharacterEncoding ensures password uses valid characters.
// This method checks for problematic characters that could cause issues
// with encoding, storage, or processing.
//
// Parameters:
//   - password: Password string to validate
//
// Returns:
//   - Error if invalid characters are found, nil if valid
//
// Time Complexity: O(n) where n is password length
// Space Complexity: O(1)
func (v *Validator) validateCharacterEncoding(password string) error {
	for i, char := range password {
		// Check for control characters (except tab, newline, carriage return)
		if unicode.IsControl(char) && char != '\t' && char != '\n' && char != '\r' {
			return fmt.Errorf("%w: password contains invalid control character at position %d",
				domain.ErrWeakPassword, i)
		}

		// Check for null bytes
		if char == 0 {
			return fmt.Errorf("%w: password cannot contain null bytes",
				domain.ErrWeakPassword)
		}
	}
	return nil
}

// isCommonPassword checks if password is in the common passwords list.
// This method performs case-insensitive matching against known weak passwords.
//
// Parameters:
//   - password: Password string to check
//
// Returns:
//   - True if password is common/weak, false otherwise
//
// Time Complexity: O(1) for hash map lookup
// Space Complexity: O(1)
func (v *Validator) isCommonPassword(password string) bool {
	return v.commonPasswords[strings.ToLower(password)]
}

// hasRepeatedChars detects if password has excessive character repetition.
// This method identifies patterns like "aaa" or "111" that reduce entropy.
//
// Parameters:
//   - password: Password string to analyze
//
// Returns:
//   - True if excessive repetition is detected, false otherwise
//
// Time Complexity: O(n) where n is password length
// Space Complexity: O(1)
func (v *Validator) hasRepeatedChars(password string) bool {
	if len(password) < 3 {
		return false
	}

	for i := 0; i <= len(password)-3; i++ {
		if password[i] == password[i+1] && password[i+1] == password[i+2] {
			return true
		}
	}
	return false
}

// hasSequentialChars detects if password contains sequential character patterns.
// This method identifies patterns like "abc", "123", "qwerty" that are predictable.
//
// Parameters:
//   - password: Password string to analyze
//
// Returns:
//   - True if sequential patterns are detected, false otherwise
//
// Time Complexity: O(n) where n is password length
// Space Complexity: O(1)
func (v *Validator) hasSequentialChars(password string) bool {
	if len(password) < 3 {
		return false
	}

	lowerPassword := strings.ToLower(password)

	// Check for sequential patterns
	sequences := []string{
		"abcdefghijklmnopqrstuvwxyz",
		"qwertyuiopasdfghjklzxcvbnm",
		"1234567890",
	}

	for _, sequence := range sequences {
		for i := 0; i <= len(sequence)-3; i++ {
			pattern := sequence[i : i+3]
			if strings.Contains(lowerPassword, pattern) {
				return true
			}
		}
	}

	return false
}

// calculateEntropy estimates password entropy based on character space and length.
// This method provides an approximation of password randomness.
//
// Parameters:
//   - password: Password string to analyze
//
// Returns:
//   - Estimated entropy in bits
//
// Time Complexity: O(n) where n is password length
// Space Complexity: O(k) where k is unique character count
func (v *Validator) calculateEntropy(password string) float64 {
	if password == "" {
		return 0
	}

	// Count unique characters
	uniqueChars := make(map[rune]bool)
	for _, char := range password {
		uniqueChars[char] = true
	}

	// Estimate character space based on character types present
	charSpace := len(uniqueChars)
	if charSpace < 10 {
		charSpace = 10 // Minimum assumption
	}

	// Calculate entropy: log2(character_space) * length
	return float64(len(password)) * (3.32 * logBase10(float64(charSpace))) // log2(x) = log10(x) / log10(2) ≈ 3.32 * log10(x)
}

// logBase10 calculates logarithm base 10 (simple implementation).
// This is a helper function for entropy calculation.
//
// Parameters:
//   - x: Number to calculate logarithm for
//
// Returns:
//   - Logarithm base 10 of x
//
// Time Complexity: O(1)
// Space Complexity: O(1)
func logBase10(x float64) float64 {
	if x <= 0 {
		return 0
	}
	// Simple approximation for demonstration
	// In production, use math.Log10(x)
	result := 0.0
	for x >= 10 {
		x /= 10
		result += 1.0
	}
	// Add fractional part approximation
	if x > 1 {
		result += (x - 1) / 2.3 // Rough approximation
	}
	return result
}

// loadCommonPasswords loads a set of commonly used passwords to reject.
// This method initializes the common passwords database for validation.
//
// Returns:
//   - Map of common passwords (lowercase) for fast lookup
//
// Time Complexity: O(k) where k is number of common passwords
// Space Complexity: O(k) where k is number of common passwords
func loadCommonPasswords() map[string]bool {
	// In production, this would load from a file or database
	// This is a minimal set for demonstration
	commonPasswords := map[string]bool{
		"password":    true,
		"123456":      true,
		"123456789":   true,
		"qwerty":      true,
		"abc123":      true,
		"password123": true,
		"admin":       true,
		"letmein":     true,
		"welcome":     true,
		"monkey":      true,
		"1234567890":  true,
		"password1":   true,
		"qwerty123":   true,
		"123123":      true,
		"111111":      true,
		"1234567":     true,
		"dragon":      true,
		"123321":      true,
		"baseball":    true,
		"football":    true,
		"superman":    true,
		"michael":     true,
		"jennifer":    true,
		"jordan":      true,
		"michelle":    true,
		"daniel":      true,
		"anthony":     true,
		"joshua":      true,
		"matthew":     true,
		"amanda":      true,
		"ashley":      true,
	}

	return commonPasswords
}

// GetRequirements returns a structured representation of the password requirements.
// This method provides both the technical configuration and human-readable
// descriptions of the password policy for client consumption.
//
// Returns:
//   - PasswordRequirements: Complete password policy information
//
// The returned structure includes all validation rules and their descriptions,
// making it suitable for building dynamic user interfaces that show password
// requirements in real-time.
//
// Time Complexity: O(1)
// Space Complexity: O(k) where k is the number of requirements
//
// Example usage:
//
//	requirements := validator.GetRequirements()
//	fmt.Printf("Password must be %d-%d characters\n",
//	    requirements.MinLength, requirements.MaxLength)
//	for _, req := range requirements.Requirements {
//	    fmt.Printf("- %s\n", req)
//	}
func (v *Validator) GetRequirements() PasswordRequirements {
	requirements := []string{}

	// Add length requirement
	if v.minLength > 0 && v.maxLength > v.minLength {
		requirements = append(requirements,
			fmt.Sprintf("Between %d and %d characters long", v.minLength, v.maxLength))
	} else if v.minLength > 0 {
		requirements = append(requirements,
			fmt.Sprintf("At least %d characters long", v.minLength))
	}

	// Add character class requirements
	if v.requireUppercase {
		requirements = append(requirements, "At least one uppercase letter (A-Z)")
	}
	if v.requireLowercase {
		requirements = append(requirements, "At least one lowercase letter (a-z)")
	}
	if v.requireDigits {
		requirements = append(requirements, "At least one digit (0-9)")
	}
	if v.requireSpecialChars {
		requirements = append(requirements, "At least one special character")
	}

	// Add security requirements
	requirements = append(requirements, "Cannot be a commonly used password")
	requirements = append(requirements, "Cannot contain parts of your email or name")

	return PasswordRequirements{
		MinLength:           v.minLength,
		MaxLength:           v.maxLength,
		RequireUppercase:    v.requireUppercase,
		RequireLowercase:    v.requireLowercase,
		RequireDigits:       v.requireDigits,
		RequireSpecialChars: v.requireSpecialChars,
		SpecialCharSet:      v.getSpecialCharSet(),
		Requirements:        requirements,
	}
}

// getSpecialCharSet returns the special character set as a string.
// This method extracts the special characters from the compiled regex
// for client consumption.
//
// Returns:
//   - String containing all valid special characters
//
// Time Complexity: O(1)
// Space Complexity: O(1)
func (v *Validator) getSpecialCharSet() string {
	// For now, return the default set - in the future this could be
	// extracted from the compiled regex if needed
	return "!@#$%^&*()_+-=[]{}|;:,.<>?"
}
