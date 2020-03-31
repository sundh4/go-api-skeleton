package utils

import (
	"encoding/json"
	"net/http"
	"net/mail"
	"os"
	"strconv"

	"github.com/go-gomail/gomail"
	"github.com/matcornic/hermes/v2"
)

// Message function
func Message(status bool, message string) map[string]interface{} {
	return map[string]interface{}{"isSuccess": status, "message": message}
}

// Respond function
func Respond(w http.ResponseWriter, data map[string]interface{}) {
	w.Header().Add("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

type smtpAuthentication struct {
	Server         string
	Port           int
	SenderEmail    string
	SenderIdentity string
	SMTPUser       string
	SMTPPassword   string
}

// sendOptions are options for sending an email
type sendOptions struct {
	To      string
	Subject string
}

type example interface {
	Email() hermes.Email
	Name() string
}

// SentConfirmEmail function to sent confirmation token to email
func SentConfirmEmail(name, mailto, url string) error {
	// Init header
	h := hermes.Hermes{
		// Optional Theme
		// Theme: new(Default)
		Product: hermes.Product{
			// Appears in header & footer of e-mails
			Name: "OMITS",
			Link: "https://www.omitsindo.com/",
			// Optional product logo
			Logo: "https://www.omitsindo.com/themes/mehedi-megakit/assets/images/icon/favicon.ico",
		},
	}
	// Init email content
	email := hermes.Email{
		Body: hermes.Body{
			Name: name,
			Intros: []string{
				"Welcome to Omits! We're very excited to have you on board.",
			},
			Actions: []hermes.Action{
				{
					Instructions: "To get started with Omits, please click here:",
					Button: hermes.Button{
						Color: "#22BC66", // Optional action button color
						Text:  "Confirm your account",
						Link:  url,
					},
				},
			},
			Outros: []string{
				"Need help, or have questions? Just reply to this email, we'd love to help.",
			},
		},
	}
	// Generate an HTML email with the provided contents (for modern clients)
	emailBody, err := h.GenerateHTML(email)
	if err != nil {
		panic(err) // Tip: Handle error with something else than a panic ;)
	}
	// Generate the plaintext version of the e-mail (for clients that do not support xHTML)
	emailText, err := h.GeneratePlainText(email)
	if err != nil {
		panic(err) // Tip: Handle error with something else than a panic ;)
	}
	// SMTP Setup
	port, _ := strconv.Atoi(os.Getenv("SMTP_PORT"))
	smtpConfig := smtpAuthentication{
		Server:         os.Getenv("SMTP_HOST"),
		Port:           port,
		SenderEmail:    os.Getenv("SENDER_EMAIL"),
		SenderIdentity: os.Getenv("SENDER_IDENTITY"),
		SMTPPassword:   os.Getenv("SMTP_PASS"),
		SMTPUser:       os.Getenv("SMTP_USER"),
	}
	options := sendOptions{
		To:      mailto,
		Subject: "Account Confirmation",
	}
	from := mail.Address{
		Name:    smtpConfig.SenderIdentity,
		Address: smtpConfig.SenderEmail,
	}

	m := gomail.NewMessage()
	m.SetHeader("From", from.String())
	m.SetHeader("To", options.To)
	m.SetHeader("Subject", options.Subject)

	m.SetBody("text/plain", emailText)
	m.AddAlternative("text/html", emailBody)

	d := gomail.NewDialer(smtpConfig.Server, smtpConfig.Port, smtpConfig.SMTPUser, smtpConfig.SMTPPassword)

	return d.DialAndSend(m)
}

// EmailNotifAccount function to sent email notification regarding user creation
func EmailNotifAccount(name, mailto, url string) error {
	// Init header
	h := hermes.Hermes{
		// Optional Theme
		// Theme: new(Default)
		Product: hermes.Product{
			// Appears in header & footer of e-mails
			Name: "OMITS",
			Link: "https://www.omitsindo.com/",
			// Optional product logo
			Logo: "https://www.omitsindo.com/themes/mehedi-megakit/assets/images/icon/favicon.ico",
		},
	}
	// Init email content
	email := hermes.Email{
		Body: hermes.Body{
			Name: name,
			Intros: []string{
				"Your account has been activated.",
			},
			Actions: []hermes.Action{
				{
					Instructions: "To get started, just visit our website:",
					Button: hermes.Button{
						Color: "#22BC66", // Optional action button color
						Text:  "OMITS Website",
						Link:  url,
					},
				},
			},
			Outros: []string{
				"Need help, or have questions? Just reply to this email, we'd love to help.",
			},
		},
	}
	// Generate an HTML email with the provided contents (for modern clients)
	emailBody, err := h.GenerateHTML(email)
	if err != nil {
		panic(err) // Tip: Handle error with something else than a panic ;)
	}
	// Generate the plaintext version of the e-mail (for clients that do not support xHTML)
	emailText, err := h.GeneratePlainText(email)
	if err != nil {
		panic(err) // Tip: Handle error with something else than a panic ;)
	}
	// SMTP Setup
	port, _ := strconv.Atoi(os.Getenv("SMTP_PORT"))
	smtpConfig := smtpAuthentication{
		Server:         os.Getenv("SMTP_HOST"),
		Port:           port,
		SenderEmail:    os.Getenv("SENDER_EMAIL"),
		SenderIdentity: os.Getenv("SENDER_IDENTITY"),
		SMTPPassword:   os.Getenv("SMTP_PASS"),
		SMTPUser:       os.Getenv("SMTP_USER"),
	}
	options := sendOptions{
		To:      mailto,
		Subject: "Welcome to OMITS",
	}
	from := mail.Address{
		Name:    smtpConfig.SenderIdentity,
		Address: smtpConfig.SenderEmail,
	}

	m := gomail.NewMessage()
	m.SetHeader("From", from.String())
	m.SetHeader("To", options.To)
	m.SetHeader("Subject", options.Subject)

	m.SetBody("text/plain", emailText)
	m.AddAlternative("text/html", emailBody)

	d := gomail.NewDialer(smtpConfig.Server, smtpConfig.Port, smtpConfig.SMTPUser, smtpConfig.SMTPPassword)

	return d.DialAndSend(m)
}
