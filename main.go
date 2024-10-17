package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"os"
	"strings"
	"github.com/dlclark/regexp2"
	"github.com/gookit/color"
	"net/smtp"
)

var (
	client       = &http.Client{}
	cookieClient = &http.Client{}
	in           = color.HiBlue.Render
)

type Account struct {
	Email    string
	Username string
	Password string
}

func decode(toDecode []byte) map[string]string {
	var output map[string]string
	json.Unmarshal([]byte(toDecode), &output)
	return output
}

func getCSRF() string {
	regx := regexp2.MustCompile("(?<=\"csrf_token\":\")\\w+", 0)

	req, _ := http.NewRequest("GET", "https://www.instagram.com/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Brave Chrome/83.0.4103.116 Safari/537.36")
	resp, _ := client.Do(req)
	body, _ := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()

	if m, _ := regx.FindStringMatch(string(body)); m != nil {
		return m.String()
	}
	return ""
}

func updateDetails(csrfToken string, email string, username string) bool {
	data := "first_name=&email=" + email + "&username=" + username + "&phone_number=&biography=" + "" + "&external_url=&chaining_enabled=on"
	req, _ := http.NewRequest("POST", "https://www.instagram.com/accounts/edit/", bytes.NewBuffer([]byte(data)))
	req.Header.Set("accept", "*/*")
	req.Header.Set("accept-language", "en-US,en;q=0.9")
	req.Header.Set("content-type", "application/x-www-form-urlencoded")
	req.Header.Set("sec-fetch-dest", "empty")
	req.Header.Set("sec-fetch-mode", "cors")
	req.Header.Set("sec-fetch-site", "same-origin")
	req.Header.Set("x-csrftoken", csrfToken)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Brave Chrome/83.0.4103.116 Safari/537.36")
	resp, err := cookieClient.Do(req)

	if err != nil {
		color.Red.Println("An error has occured")
		fmt.Scanln()
	}

	body, _ := ioutil.ReadAll(resp.Body)
	response := string(body)
	defer resp.Body.Close()

	fmt.Printf("%v - Update Detail Resp: %v", resp.StatusCode, response)

	if strings.Contains(response, "Please wait a few minutes before you try again") {
		color.Red.Println("[+] Rate limited")
	}

	if strings.Contains(response, "\"status\":\"ok\"") {
		color.Green.Printf("[+] Successfully updated username to %s\n", username)
		return true
	}

	return false
}

func urlCheck(check string) bool {
	req, _ := http.NewRequest("GET", "https://www.instagram.com/"+check, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Brave Chrome/83.0.4103.116 Safari/537.36")
	resp, _ := client.Do(req)

	body, _ := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		color.Green.Printf("[+] [%s] available\n", check)
		return true
	} else if resp.StatusCode == 200 && strings.Contains(string(body), "Login • Instagram") {
		color.Red.Println("[+] Failed to check username")
		return false
	} else {
		color.Yellow.Printf("[+] [%s] currently unavailable\n", check)
		return false
	}
}

func createCheck(check string) bool {
	csrfToken := getCSRF()
	data := "username=" + check + "&email=random@gmail.com&first_name=firstname&opt_into_one_tap=false&enc_password=#PWD_INSTAGRAM_BROWSER:0:0:password0000"
	req, _ := http.NewRequest("POST", "https://www.instagram.com/accounts/web_create_ajax/attempt/", bytes.NewBuffer([]byte(data)))
	req.Header.Set("accept", "*/*")
	req.Header.Set("accept-language", "en-US,en;q=0.9")
	req.Header.Set("content-type", "application/x-www-form-urlencoded")
	req.Header.Set("sec-fetch-dest", "empty")
	req.Header.Set("sec-fetch-mode", "cors")
	req.Header.Set("sec-fetch-site", "same-origin")
	req.Header.Set("x-csrftoken", csrfToken)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Brave Chrome/83.0.4103.116 Safari/537.36")

	resp, err := client.Do(req)

	if err != nil {
		fmt.Println("Error occured")
		fmt.Scanln()
	}

	body, _ := ioutil.ReadAll(resp.Body)
	response := string(body)
	defer resp.Body.Close()

	if strings.Contains(response, "spam") {
		color.Red.Println("[+] Spam detected")
		fmt.Println(response)
		return false
	}

	if strings.Contains(response, "try again") || resp.StatusCode == 403 {
		color.Red.Println("[+] Rate limited")
		return false
	} else if !strings.Contains(response, "\"username\":") && !strings.Contains(response, "username isn't available") && !strings.Contains(response, "username_is_taken") && !strings.Contains(response, "username_held_by_others") && resp.StatusCode != 403 {
		color.Green.Printf("[+] [%s] available\n", check)
		fmt.Println(response)
		return true

	} else {
		color.Yellow.Printf("[+] [%s] currently unavailable\n", check)
		return false
	}
}

func login(username string, password string) (*http.Response, string) {
	data := "username=" + username + "&enc_password=" + password + "&queryParams={}&optIntoOneTap=false"
	req, _ := http.NewRequest("POST", "https://www.instagram.com/accounts/login/ajax/", bytes.NewBuffer([]byte(data)))
	csrfToken := getCSRF()

	req.Header.Set("accept", "*/*")
	req.Header.Set("accept-language", "en-US,en;q=0.9")
	req.Header.Set("content-type", "application/x-www-form-urlencoded")
	req.Header.Set("sec-fetch-dest", "empty")
	req.Header.Set("sec-fetch-mode", "cors")
	req.Header.Set("sec-fetch-site", "same-origin")
	req.Header.Set("x-csrftoken", csrfToken)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Brave Chrome/83.0.4103.116 Safari/537.36")

	jar, _ := cookiejar.New(nil)
	cookieClient = &http.Client{Jar: jar}

	resp, err := cookieClient.Do(req)

	if err != nil {
		fmt.Println("Error occured when trying to login.")
		fmt.Scanln()
	}
	return resp, resp.Cookies()[0].Value
}

func getLines(path string) []string {
	file, err := os.Open(path)
	if err != nil {
		color.Red.Println("\nUnable to open text file:", path)
		color.Red.Printf("Make sure path \"%v\" is available\n", path)
		fmt.Scanln()
	}
	defer file.Close()
	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines
}

func readAccFromEnv() Account {
	return Account{
		Email:    os.Getenv("IG_EMAIL"),
		Username: os.Getenv("IG_USERNAME"),
		Password: os.Getenv("IG_PASSWORD"),
	}
}

func getTargetsFromEnv() []string {
	targetsStr := os.Getenv("IG_TARGETS")
	return strings.Split(targetsStr, ",")
}

func sendEmail(to, subject, body string) error {
	from := os.Getenv("SMTP_FROM")
	password := os.Getenv("SMTP_PASSWORD")
	smtpHost := os.Getenv("SMTP_HOST")
	smtpPort := os.Getenv("SMTP_PORT")

	msg := []byte("To: " + to + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"\r\n" +
		body + "\r\n")

	auth := smtp.PlainAuth("", from, password, smtpHost)

	err := smtp.SendMail(smtpHost+":"+smtpPort, auth, from, []string{to}, msg)
	if err != nil {
		return err
	}
	return nil
}

func generateEmailContent(targets []string, results map[string]bool) string {
	content := "IG Sniper Results:\n\n"
	for _, target := range targets {
		status := "Unavailable"
		if results[target] {
			status = "Available"
		}
		content += fmt.Sprintf("Username: %s - Status: %s\n", target, status)
	}
	return content
}

func logDetails(details *strings.Builder, format string, a ...interface{}) {
	details.WriteString(fmt.Sprintf(format+"\n", a...))
}

func main() {
	fmt.Print("\033[H\033[2J")

	var details strings.Builder
	logDetails(&details, "IG Sniper Script Started")

	acc := readAccFromEnv()
	accTargets := getTargetsFromEnv()

	emailLogin := acc.Email
	usernameLogin := acc.Username
	passwordLogin := acc.Password

	if len(emailLogin) < 1 {
		logDetails(&details, "Error: Email not provided in environment variables")
		color.Red.Println("Email not provided in environment variables")
		return
	}

	logDetails(&details, "Email: %s", emailLogin)
	logDetails(&details, "Username: %s", usernameLogin)
	logDetails(&details, "Password: %s", strings.Repeat("*", len(passwordLogin)))

	logDetails(&details, "Attempting to login through Instagram API...")

	resp, csrf := login(usernameLogin, "#PWD_INSTAGRAM_BROWSER:0:0:"+passwordLogin)
	body, _ := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()

	if strings.Contains(string(body), "\"authenticated\":true") {
		logDetails(&details, "Successfully logged in")
		logDetails(&details, "Authenticated: True, userID: %s", decode(body)["userId"])

		results := make(map[string]bool)

		for _, target := range accTargets {
			logDetails(&details, "Checking username: %s", target)

			if createCheck(target) {
				results[target] = true
				logDetails(&details, "Username %s is available", target)
				if updateDetails(csrf, emailLogin, target) {
					logDetails(&details, "Successfully claimed username: %s", target)
					emailSubject := "Instagram Username Claimed"
					emailBody := fmt.Sprintf("The username %s has been successfully claimed.\n\nDetails:\n%s", target, details.String())
					err := sendEmail(emailLogin, emailSubject, emailBody)
					if err != nil {
						logDetails(&details, "Failed to send email notification: %v", err)
					} else {
						logDetails(&details, "Email notification sent to %s", emailLogin)
					}
					return // Exit the program after successfully claiming the username
				}
			} else {
				results[target] = false
			}
		}

		// Send email with results
		emailSubject := "IG Sniper Results"
		emailBody := generateEmailContent(accTarget
			s, results)
		err := sendEmail(emailLogin, emailSubject, emailBody)
		if err != nil {
			logDetails(&details, "Failed to send results email: %v", err)
		} else {
			logDetails(&details, "Results email sent to %s", emailLogin)
		}
	} else {
		logDetails(&details, "Unable to log in. Status Code: %v", resp.StatusCode)
		logDetails(&details, "Login response: %s", string(body))
	}
}
