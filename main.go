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
	"time"
	"net/url"
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
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error getting CSRF token:", err)
		return ""
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)

	if m, _ := regx.FindStringMatch(string(body)); m != nil {
		return m.String()
	}
	return ""
}

func updateDetails(csrfToken string, email string, username string) (bool, error) {
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
		return true, nil
	}

	return false, nil
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
		fmt.Printf("Error occurred during createCheck: %v\n", err)
		return false
	}

	body, _ := ioutil.ReadAll(resp.Body)
	response := string(body)
	defer resp.Body.Close()

	fmt.Printf("createCheck response for %s: Status: %d, Body: %s\n", check, resp.StatusCode, response)

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

func login(username string, password string) (*http.Response, string, error) {
	csrfToken := getCSRF()
	if csrfToken == "" {
		return nil, "", fmt.Errorf("Failed to get CSRF token")
	}

	data := fmt.Sprintf("username=%s&enc_password=#PWD_INSTAGRAM_BROWSER:0:0:%s&queryParams={}&optIntoOneTap=false", username, password)
	req, _ := http.NewRequest("POST", "https://www.instagram.com/accounts/login/ajax/", bytes.NewBuffer([]byte(data)))

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.Header.Set("Referer", "https://www.instagram.com/accounts/login/")
	req.Header.Set("x-csrftoken", csrfToken)
	req.Header.Set("X-Instagram-AJAX", "1")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Origin", "https://www.instagram.com")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Dest", "empty")

	jar, _ := cookiejar.New(nil)
	cookieClient = &http.Client{
		Jar: jar,
		Timeout: time.Second * 10,
	}

	// Set cookies
	u, _ := url.Parse("https://www.instagram.com")
	jar.SetCookies(u, []*http.Cookie{
		{Name: "csrftoken", Value: csrfToken},
	})

	resp, err := cookieClient.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("Error occurred when trying to login: %v", err)
	}

	if resp.StatusCode != 200 {
		body, _ := ioutil.ReadAll(resp.Body)
		return resp, csrfToken, fmt.Errorf("Login failed with status code %d: %s", resp.StatusCode, string(body))
	}

	return resp, csrfToken, nil
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
	fmt.Println("IG Sniper Script Started")

	var details strings.Builder
	logDetails(&details, "IG Sniper Script Started")

	// Log all environment variables (except password)
	fmt.Println("IG_EMAIL:", os.Getenv("IG_EMAIL"))
	fmt.Println("IG_USERNAME:", os.Getenv("IG_USERNAME"))
	fmt.Println("IG_TARGETS:", os.Getenv("IG_TARGETS"))
	fmt.Println("SMTP_FROM:", os.Getenv("SMTP_FROM"))
	fmt.Println("SMTP_HOST:", os.Getenv("SMTP_HOST"))
	fmt.Println("SMTP_PORT:", os.Getenv("SMTP_PORT"))

	acc := readAccFromEnv()
	accTargets := getTargetsFromEnv()

	emailLogin := acc.Email
	usernameLogin := acc.Username
	passwordLogin := acc.Password

	if len(emailLogin) < 1 {
		fmt.Println("Error: Email not provided in environment variables")
		return
	}

	fmt.Println("Email:", emailLogin)
	fmt.Println("Username:", usernameLogin)
	fmt.Println("Targets:", accTargets)

	fmt.Println("Attempting to login through Instagram API...")
	time.Sleep(2 * time.Second) // Add a delay before login

	resp, csrf, err := login(usernameLogin, passwordLogin)
	if err != nil {
		fmt.Println("Login failed:", err)
		return
	}

	body, _ := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()

	fmt.Println("Login response status:", resp.StatusCode)
	fmt.Println("Login response body:", string(body))

	var loginResponse map[string]interface{}
	json.Unmarshal(body, &loginResponse)

	if loginResponse["authenticated"] == true {
		fmt.Println("Successfully logged in")
		fmt.Println("Authenticated: True, userID:", loginResponse["userId"])

		results := make(map[string]bool)

		for _, target := range accTargets {
			fmt.Println("Checking username:", target)
			
			if createCheck(target) {
				results[target] = true
				fmt.Println("Username", target, "is available")
				updateSuccess, updateErr := updateDetails(csrf, emailLogin, target)
				if updateErr != nil {
					fmt.Printf("Error updating details for %s: %v\n", target, updateErr)
				} else if updateSuccess {
					fmt.Println("Successfully claimed username:", target)
					emailSubject := "Instagram Username Claimed"
					emailBody := fmt.Sprintf("The username %s has been successfully claimed.\n\nDetails:\n%s", target, details.String())
					err := sendEmail(emailLogin, emailSubject, emailBody)
					if err != nil {
						fmt.Println("Failed to send email notification:", err)
					} else {
						fmt.Println("Email notification sent to", emailLogin)
					}
					return // Exit the program after successfully claiming the username
				} else {
					fmt.Printf("Failed to claim username: %s\n", target)
				}
			} else {
				results[target] = false
				fmt.Printf("Username %s is not available\n", target)
			}
		}

		// Send email with results
		emailSubject := "IG Sniper Results"
		emailBody := generateEmailContent(accTargets, results)
		emailBody += "\n\nDetails:\n" + details.String()
		err := sendEmail(emailLogin, emailSubject, emailBody)

		if err != nil {
			fmt.Println("Failed to send results email:", err)
		} else {
			fmt.Println("Results email sent to", emailLogin)
		}
	} else {
		fmt.Println("Unable to log in. Authentication failed.")
		fmt.Println("Login response:", string(body))
	}
	
}

