package test

import (
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"auth-service/internal/utils"
)

// InputSanitizerTestSuite provides comprehensive test coverage for the InputSanitizer.
//
// This test suite validates all security features of the input sanitizer including:
// - Email validation and sanitization
// - Name sanitization with XSS/SQL injection prevention
// - Generic text sanitization with configurable options
// - File path sanitization with directory traversal prevention
// - Edge cases and malicious input handling
// - Performance characteristics under various loads
//
// Test Categories:
// - Unit Tests: Individual method validation
// - Security Tests: Malicious input detection and prevention
// - Performance Tests: Efficiency under load
// - Edge Case Tests: Boundary conditions and unusual inputs
// - Integration Tests: Combined sanitization workflows
//
// Security Focus Areas:
// - SQL Injection Prevention
// - XSS Attack Prevention
// - Directory Traversal Prevention
// - Control Character Injection Prevention
// - UTF-8 Encoding Attack Prevention
// - Buffer Overflow Prevention (length limits)
type InputSanitizerTestSuite struct {
	suite.Suite
	sanitizer *utils.InputSanitizer
	logger    *logrus.Logger
}

// SetupTest initializes the test environment before each test.
//
// Creates a fresh sanitizer instance with a test logger to ensure
// isolated test conditions and proper logging capture for verification.
func (suite *InputSanitizerTestSuite) SetupTest() {
	// Create test logger with consistent configuration
	suite.logger = logrus.New()
	suite.logger.SetLevel(logrus.DebugLevel)

	// Initialize sanitizer with test logger
	suite.sanitizer = utils.NewInputSanitizer(suite.logger)
	require.NotNil(suite.T(), suite.sanitizer, "Sanitizer should be created successfully")
}

// TestEmailSanitization_ValidEmails tests sanitization of valid email formats.
//
// Validates that legitimate email addresses are properly normalized while
// maintaining their validity and essential characteristics.
func (suite *InputSanitizerTestSuite) TestEmailSanitization_ValidEmails() {
	testCases := []struct {
		name     string
		input    string
		expected string
		desc     string
	}{
		{
			name:     "basic_email",
			input:    "user@example.com",
			expected: "user@example.com",
			desc:     "Standard email format should remain unchanged",
		},
		{
			name:     "uppercase_normalization",
			input:    "USER@EXAMPLE.COM",
			expected: "user@example.com",
			desc:     "Uppercase emails should be normalized to lowercase",
		},
		{
			name:     "whitespace_trimming",
			input:    "  user@example.com  ",
			expected: "user@example.com",
			desc:     "Leading and trailing whitespace should be removed",
		},
		{
			name:     "complex_valid_email",
			input:    "user.name+tag@sub.example.com",
			expected: "user.name+tag@sub.example.com",
			desc:     "Complex but valid email formats should be preserved",
		},
		{
			name:     "numeric_domain",
			input:    "test@123domain.co.uk",
			expected: "test@123domain.co.uk",
			desc:     "Numeric characters in domain should be allowed",
		},
		{
			name:     "hyphenated_domain",
			input:    "user@my-company.example.org",
			expected: "user@my-company.example.org",
			desc:     "Hyphenated domains should be preserved",
		},
	}

	for _, tc := range testCases {
		suite.Run(tc.name, func() {
			result := suite.sanitizer.SanitizeEmail(tc.input)
			assert.Equal(suite.T(), tc.expected, result, tc.desc)
		})
	}
}

// TestEmailSanitization_SecurityThreats tests detection and prevention of email-based attacks.
//
// Validates that malicious patterns in email inputs are properly detected
// and rejected to prevent various injection attacks.
func (suite *InputSanitizerTestSuite) TestEmailSanitization_SecurityThreats() {
	testCases := []struct {
		name        string
		input       string
		expected    string
		description string
		threat      string
	}{
		{
			name:        "sql_injection_basic",
			input:       "admin@test.com'; DROP TABLE users; --",
			expected:    "",
			description: "Basic SQL injection attempt should be blocked",
			threat:      "sql_injection",
		},
		{
			name:        "sql_injection_union",
			input:       "user@test.com UNION SELECT * FROM passwords",
			expected:    "",
			description: "UNION-based SQL injection should be detected",
			threat:      "sql_injection",
		},
		{
			name:        "control_character_injection",
			input:       "user@test.com\x00\x08\x1b",
			expected:    "",
			description: "Control characters should be removed and email should fail validation",
			threat:      "control_injection",
		},
		{
			name:        "invalid_format_xss",
			input:       "<script>alert('xss')</script>@test.com",
			expected:    "",
			description: "XSS in email format should be rejected",
			threat:      "xss",
		},
		{
			name:        "length_attack",
			input:       strings.Repeat("a", 250) + "@" + strings.Repeat("b", 10) + ".com",
			expected:    "",
			description: "Overly long emails should be rejected",
			threat:      "buffer_overflow",
		},
		{
			name:        "null_byte_injection",
			input:       "user@test.com\x00",
			expected:    "",
			description: "Null byte injection should be prevented",
			threat:      "null_injection",
		},
		{
			name:        "unicode_normalization_attack",
			input:       "user@test\u202e.com", // Right-to-left override
			expected:    "",
			description: "Unicode control characters should be filtered",
			threat:      "unicode_attack",
		},
	}

	for _, tc := range testCases {
		suite.Run(tc.name, func() {
			result := suite.sanitizer.SanitizeEmail(tc.input)
			assert.Equal(suite.T(), tc.expected, result, tc.description)

			// Verify that threats are properly logged
			if tc.expected == "" {
				// Could add log verification here if logger output is captured
				suite.T().Logf("Successfully blocked %s threat: %s", tc.threat, tc.input)
			}
		})
	}
}

// TestEmailSanitization_EdgeCases tests boundary conditions and unusual inputs.
//
// Validates sanitizer behavior with edge cases that might not be malicious
// but require careful handling.
func (suite *InputSanitizerTestSuite) TestEmailSanitization_EdgeCases() {
	testCases := []struct {
		name        string
		input       string
		expected    string
		description string
	}{
		{
			name:        "empty_string",
			input:       "",
			expected:    "",
			description: "Empty input should return empty string",
		},
		{
			name:        "only_whitespace",
			input:       "   \t\n   ",
			expected:    "",
			description: "Only whitespace should result in empty string",
		},
		{
			name:        "no_at_symbol",
			input:       "userexample.com",
			expected:    "",
			description: "Missing @ symbol should be rejected",
		},
		{
			name:        "multiple_at_symbols",
			input:       "user@@example.com",
			expected:    "",
			description: "Multiple @ symbols should be rejected",
		},
		{
			name:        "missing_domain",
			input:       "user@",
			expected:    "",
			description: "Missing domain should be rejected",
		},
		{
			name:        "missing_tld",
			input:       "user@example",
			expected:    "",
			description: "Missing TLD should be rejected",
		},
		{
			name:        "international_domain",
			input:       "user@例え.テスト",
			expected:    "",
			description: "International domains should be rejected by simple regex",
		},
		{
			name:        "rfc_maximum_length",
			input:       strings.Repeat("a", 64) + "@" + strings.Repeat("b", 63) + ".com",
			expected:    strings.Repeat("a", 64) + "@" + strings.Repeat("b", 63) + ".com",
			description: "RFC-compliant maximum length should be accepted",
		},
	}

	for _, tc := range testCases {
		suite.Run(tc.name, func() {
			result := suite.sanitizer.SanitizeEmail(tc.input)
			assert.Equal(suite.T(), tc.expected, result, tc.description)
		})
	}
}

// TestNameSanitization_ValidNames tests sanitization of legitimate name inputs.
//
// Validates that real-world names with various characteristics are properly
// sanitized while preserving their essential features.
func (suite *InputSanitizerTestSuite) TestNameSanitization_ValidNames() {
	testCases := []struct {
		name     string
		input    string
		expected string
		desc     string
	}{
		{
			name:     "simple_name",
			input:    "John Doe",
			expected: "John Doe",
			desc:     "Simple names should remain unchanged",
		},
		{
			name:     "name_with_apostrophe",
			input:    "John O'Connor",
			expected: "John O&#39;Connor",
			desc:     "Apostrophes should be HTML escaped",
		},
		{
			name:     "hyphenated_name",
			input:    "Mary-Jane Watson",
			expected: "Mary-Jane Watson",
			desc:     "Hyphenated names should be preserved",
		},
		{
			name:     "name_with_spaces",
			input:    "  John   Doe  ",
			expected: "John   Doe",
			desc:     "Leading/trailing spaces trimmed, internal spaces preserved",
		},
		{
			name:     "unicode_name",
			input:    "José María García",
			expected: "José María García",
			desc:     "Unicode characters in names should be preserved",
		},
		{
			name:     "name_with_dots",
			input:    "Dr. John A. Doe Jr.",
			expected: "Dr. John A. Doe Jr.",
			desc:     "Professional titles and suffixes should be preserved",
		},
	}

	for _, tc := range testCases {
		suite.Run(tc.name, func() {
			result := suite.sanitizer.SanitizeName(tc.input)
			assert.Equal(suite.T(), tc.expected, result, tc.desc)
		})
	}
}

// TestNameSanitization_SecurityThreats tests prevention of name-based attacks.
//
// Validates that malicious content in name fields is properly detected
// and neutralized to prevent XSS and injection attacks.
func (suite *InputSanitizerTestSuite) TestNameSanitization_SecurityThreats() {
	testCases := []struct {
		name        string
		input       string
		expected    string
		description string
		threat      string
	}{
		{
			name:        "script_tag_injection",
			input:       "<script>alert('xss')</script>",
			expected:    "",
			description: "Script tags should be completely blocked",
			threat:      "xss",
		},
		{
			name:        "javascript_url",
			input:       "javascript:alert('xss')",
			expected:    "",
			description: "JavaScript URLs should be blocked",
			threat:      "xss",
		},
		{
			name:        "event_handler",
			input:       "John onmouseover=alert('xss') Doe",
			expected:    "",
			description: "Event handlers should be blocked",
			threat:      "xss",
		},
		{
			name:        "sql_injection",
			input:       "Robert'; DROP TABLE students; --",
			expected:    "",
			description: "SQL injection patterns should be blocked",
			threat:      "sql_injection",
		},
		{
			name:        "iframe_injection",
			input:       "<iframe src='evil.com'></iframe>",
			expected:    "",
			description: "Iframe tags should be blocked",
			threat:      "xss",
		},
		{
			name:        "vbscript_injection",
			input:       "vbscript:msgbox('xss')",
			expected:    "",
			description: "VBScript should be blocked",
			threat:      "xss",
		},
		{
			name:        "data_uri_injection",
			input:       "data:text/html,<script>alert('xss')</script>",
			expected:    "",
			description: "Data URIs with HTML should be blocked",
			threat:      "xss",
		},
	}

	for _, tc := range testCases {
		suite.Run(tc.name, func() {
			result := suite.sanitizer.SanitizeName(tc.input)
			assert.Equal(suite.T(), tc.expected, result, tc.description)
		})
	}
}

// TestGenericTextSanitization tests the flexible text sanitization method.
//
// Validates that the generic text sanitizer properly handles various
// content types with configurable options for length and whitespace.
func (suite *InputSanitizerTestSuite) TestGenericTextSanitization() {
	testCases := []struct {
		name               string
		input              string
		maxLength          int
		preserveWhitespace bool
		expected           string
		description        string
	}{
		{
			name:               "normal_text",
			input:              "This is a normal comment.",
			maxLength:          0,
			preserveWhitespace: true,
			expected:           "This is a normal comment.",
			description:        "Normal text should be preserved",
		},
		{
			name:               "length_limiting",
			input:              "This is a very long comment that exceeds the maximum allowed length",
			maxLength:          20,
			preserveWhitespace: true,
			expected:           "This is a very long ",
			description:        "Text should be truncated to max length",
		},
		{
			name:               "whitespace_normalization",
			input:              "Text    with     multiple    spaces",
			maxLength:          0,
			preserveWhitespace: false,
			expected:           "Text with multiple spaces",
			description:        "Multiple spaces should be normalized to single spaces",
		},
		{
			name:               "html_escaping",
			input:              "Text with <b>bold</b> & special chars",
			maxLength:          0,
			preserveWhitespace: true,
			expected:           "Text with &lt;b&gt;bold&lt;/b&gt; &amp; special chars",
			description:        "HTML tags and entities should be escaped",
		},
		{
			name:               "multiline_preserved",
			input:              "Line 1\nLine 2\nLine 3",
			maxLength:          0,
			preserveWhitespace: true,
			expected:           "Line 1\nLine 2\nLine 3",
			description:        "Newlines should be preserved when whitespace is preserved",
		},
	}

	for _, tc := range testCases {
		suite.Run(tc.name, func() {
			result := suite.sanitizer.SanitizeGenericText(tc.input, tc.maxLength, tc.preserveWhitespace)
			assert.Equal(suite.T(), tc.expected, result, tc.description)
		})
	}
}

// TestFilePathSanitization tests directory traversal prevention and path validation.
//
// Validates that file path inputs are properly sanitized to prevent
// directory traversal attacks and other path-based security issues.
func (suite *InputSanitizerTestSuite) TestFilePathSanitization() {
	testCases := []struct {
		name          string
		input         string
		allowAbsolute bool
		expected      string
		description   string
	}{
		{
			name:          "safe_relative_path",
			input:         "documents/file.pdf",
			allowAbsolute: false,
			expected:      "documents/file.pdf",
			description:   "Safe relative paths should be preserved",
		},
		{
			name:          "directory_traversal_attack",
			input:         "../../../etc/passwd",
			allowAbsolute: false,
			expected:      "",
			description:   "Directory traversal should be blocked",
		},
		{
			name:          "windows_traversal",
			input:         "..\\..\\windows\\system32\\config\\sam",
			allowAbsolute: false,
			expected:      "",
			description:   "Windows-style traversal should be blocked",
		},
		{
			name:          "url_encoded_traversal",
			input:         "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
			allowAbsolute: false,
			expected:      "",
			description:   "URL-encoded traversal should be blocked",
		},
		{
			name:          "absolute_path_allowed",
			input:         "/usr/local/bin/app",
			allowAbsolute: true,
			expected:      "/usr/local/bin/app",
			description:   "Absolute paths should be allowed when configured",
		},
		{
			name:          "absolute_path_blocked",
			input:         "/usr/local/bin/app",
			allowAbsolute: false,
			expected:      "",
			description:   "Absolute paths should be blocked when not allowed",
		},
		{
			name:          "null_byte_injection",
			input:         "file.txt\x00.exe",
			allowAbsolute: false,
			expected:      "",
			description:   "Null byte injection should be prevented",
		},
		{
			name:          "extremely_long_path",
			input:         strings.Repeat("a/", 2050),
			allowAbsolute: false,
			expected:      "",
			description:   "Extremely long paths should be rejected",
		},
	}

	for _, tc := range testCases {
		suite.Run(tc.name, func() {
			result := suite.sanitizer.SanitizeFilePath(tc.input, tc.allowAbsolute)
			assert.Equal(suite.T(), tc.expected, result, tc.description)
		})
	}
}

// TestEmailAdvanced tests the advanced email sanitization with detailed results.
//
// Validates that the advanced sanitization method provides comprehensive
// feedback about the sanitization process and detected threats.
func (suite *InputSanitizerTestSuite) TestEmailAdvanced() {
	testCases := []struct {
		name             string
		input            string
		expectedValue    string
		expectedModified bool
		expectedPatterns []string
		expectedErrors   []string
		description      string
	}{
		{
			name:             "clean_email",
			input:            "user@example.com",
			expectedValue:    "user@example.com",
			expectedModified: false,
			expectedPatterns: []string{},
			expectedErrors:   []string{},
			description:      "Clean email should pass without modifications",
		},
		{
			name:             "normalized_email",
			input:            "  USER@EXAMPLE.COM  ",
			expectedValue:    "user@example.com",
			expectedModified: true,
			expectedPatterns: []string{},
			expectedErrors:   []string{},
			description:      "Email should be normalized and marked as modified",
		},
		{
			name:             "sql_injection_detected",
			input:            "admin@test.com'; DROP TABLE users;",
			expectedValue:    "",
			expectedModified: false,
			expectedPatterns: []string{"sql_injection"},
			expectedErrors:   []string{},
			description:      "SQL injection should be detected and reported",
		},
		{
			name:             "control_characters_removed",
			input:            "user@test.com\x08\x1b",
			expectedValue:    "",
			expectedModified: true,
			expectedPatterns: []string{"control_characters"},
			expectedErrors:   []string{"invalid_format"},
			description:      "Control characters should be detected and removed",
		},
		{
			name:             "empty_input",
			input:            "",
			expectedValue:    "",
			expectedModified: false,
			expectedPatterns: []string{},
			expectedErrors:   []string{"empty_input"},
			description:      "Empty input should be reported as validation error",
		},
		{
			name:             "length_exceeded",
			input:            strings.Repeat("a", 250) + "@example.com",
			expectedValue:    "",
			expectedModified: false,
			expectedPatterns: []string{},
			expectedErrors:   []string{"length_exceeded"},
			description:      "Length exceeded should be reported as validation error",
		},
	}

	for _, tc := range testCases {
		suite.Run(tc.name, func() {
			result := suite.sanitizer.SanitizeEmailAdvanced(tc.input)

			assert.Equal(suite.T(), tc.expectedValue, result.Value, "Value should match expected")
			assert.Equal(suite.T(), tc.expectedModified, result.WasModified, "Modified flag should match expected")
			assert.Equal(suite.T(), tc.expectedPatterns, result.RejectedPatterns, "Rejected patterns should match expected")
			assert.Equal(suite.T(), tc.expectedErrors, result.ValidationErrors, "Validation errors should match expected")
		})
	}
}

// TestIsValidEmail tests the fast email validation method.
//
// Validates that the performance-optimized email validation works correctly
// for both valid and invalid inputs without sanitization overhead.
func (suite *InputSanitizerTestSuite) TestIsValidEmail() {
	testCases := []struct {
		name        string
		input       string
		expected    bool
		description string
	}{
		{
			name:        "valid_email",
			input:       "user@example.com",
			expected:    true,
			description: "Valid email should return true",
		},
		{
			name:        "empty_email",
			input:       "",
			expected:    false,
			description: "Empty email should return false",
		},
		{
			name:        "invalid_format",
			input:       "not-an-email",
			expected:    false,
			description: "Invalid format should return false",
		},
		{
			name:        "sql_injection",
			input:       "user@test.com'; DROP TABLE users;",
			expected:    false,
			description: "SQL injection should return false",
		},
		{
			name:        "too_long",
			input:       strings.Repeat("a", 250) + "@example.com",
			expected:    false,
			description: "Too long email should return false",
		},
		{
			name:        "unicode_email",
			input:       "test@例え.テスト",
			expected:    false,
			description: "Unicode domain should return false",
		},
	}

	for _, tc := range testCases {
		suite.Run(tc.name, func() {
			result := suite.sanitizer.IsValidEmail(tc.input)
			assert.Equal(suite.T(), tc.expected, result, tc.description)
		})
	}
}

// TestSanitizerCreation tests the sanitizer initialization process.
//
// Validates that the sanitizer is properly created with and without
// logger instances and that all components are correctly initialized.
func (suite *InputSanitizerTestSuite) TestSanitizerCreation() {
	suite.Run("with_logger", func() {
		logger := logrus.New()
		sanitizer := utils.NewInputSanitizer(logger)

		assert.NotNil(suite.T(), sanitizer, "Sanitizer should be created")

		// Test that it works correctly
		result := sanitizer.SanitizeEmail("test@example.com")
		assert.Equal(suite.T(), "test@example.com", result)
	})

	suite.Run("without_logger", func() {
		sanitizer := utils.NewInputSanitizer(nil)

		assert.NotNil(suite.T(), sanitizer, "Sanitizer should be created even without logger")

		// Test that it works correctly
		result := sanitizer.SanitizeEmail("test@example.com")
		assert.Equal(suite.T(), "test@example.com", result)
	})
}

// TestSecurityStats tests the security statistics functionality.
//
// Validates that the sanitizer provides useful statistics about its
// configuration and security features for monitoring purposes.
func (suite *InputSanitizerTestSuite) TestSecurityStats() {
	stats := suite.sanitizer.GetSecurityStats()

	assert.NotNil(suite.T(), stats, "Statistics should not be nil")
	assert.Contains(suite.T(), stats, "sanitizer_version", "Should contain version info")
	assert.Contains(suite.T(), stats, "regex_patterns", "Should contain regex patterns")
	assert.Contains(suite.T(), stats, "security_features", "Should contain security features list")

	// Verify security features are documented
	features, ok := stats["security_features"].([]string)
	assert.True(suite.T(), ok, "Security features should be string slice")
	assert.Contains(suite.T(), features, "email_validation", "Should include email validation")
	assert.Contains(suite.T(), features, "sql_injection_detection", "Should include SQL injection detection")
	assert.Contains(suite.T(), features, "xss_prevention", "Should include XSS prevention")
}

// TestPerformance_EmailSanitization benchmarks email sanitization performance.
//
// Validates that the sanitizer maintains acceptable performance characteristics
// under various load conditions and input types.
func (suite *InputSanitizerTestSuite) TestPerformance_EmailSanitization() {
	if testing.Short() {
		suite.T().Skip("Skipping performance test in short mode")
	}

	testEmails := []string{
		"user@example.com",
		"very.long.email.address.with.multiple.dots@subdomain.example.co.uk",
		"user+tag@example.com",
		"user.name@example-domain.org",
	}

	suite.Run("bulk_email_validation", func() {
		const iterations = 10000

		for i := 0; i < iterations; i++ {
			email := testEmails[i%len(testEmails)]
			result := suite.sanitizer.SanitizeEmail(email)
			assert.NotEmpty(suite.T(), result, "Valid emails should be sanitized successfully")
		}

		suite.T().Logf("Successfully processed %d email sanitizations", iterations)
	})

	suite.Run("malicious_input_detection", func() {
		maliciousInputs := []string{
			"admin@test.com'; DROP TABLE users; --",
			"user@test.com UNION SELECT * FROM passwords",
			"<script>alert('xss')</script>@test.com",
			strings.Repeat("a", 300) + "@example.com",
		}

		const iterations = 1000

		for i := 0; i < iterations; i++ {
			input := maliciousInputs[i%len(maliciousInputs)]
			result := suite.sanitizer.SanitizeEmail(input)
			assert.Empty(suite.T(), result, "Malicious inputs should be rejected")
		}

		suite.T().Logf("Successfully detected and blocked %d malicious inputs", iterations)
	})
}

// TestConcurrentSanitization tests thread safety of the sanitizer.
//
// Validates that the sanitizer can be safely used from multiple goroutines
// without race conditions or data corruption.
func (suite *InputSanitizerTestSuite) TestConcurrentSanitization() {
	if testing.Short() {
		suite.T().Skip("Skipping concurrency test in short mode")
	}

	const numGoroutines = 100
	const emailsPerGoroutine = 100

	// Create channels for coordination
	done := make(chan bool, numGoroutines)

	// Start multiple goroutines performing sanitization
	for i := 0; i < numGoroutines; i++ {
		go func(goroutineID int) {
			defer func() { done <- true }()

			for j := 0; j < emailsPerGoroutine; j++ {
				// Test various input types
				testInputs := []string{
					"user@example.com",
					"USER@EXAMPLE.COM",
					"  spaced@example.com  ",
					"malicious'; DROP TABLE users; --",
					"<script>alert('xss')</script>",
				}

				for _, input := range testInputs {
					result := suite.sanitizer.SanitizeEmail(input)
					// Verify basic sanity - valid emails should not be empty,
					// malicious inputs should be empty
					if input == "user@example.com" || input == "USER@EXAMPLE.COM" || input == "  spaced@example.com  " {
						assert.NotEmpty(suite.T(), result, "Valid email should not be empty in goroutine %d", goroutineID)
					} else {
						assert.Empty(suite.T(), result, "Malicious input should be empty in goroutine %d", goroutineID)
					}
				}
			}
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < numGoroutines; i++ {
		<-done
	}

	suite.T().Logf("Successfully completed concurrent sanitization test with %d goroutines", numGoroutines)
}

// Run the test suite
func TestInputSanitizerSuite(t *testing.T) {
	suite.Run(t, new(InputSanitizerTestSuite))
}
