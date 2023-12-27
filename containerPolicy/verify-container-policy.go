package containerpolicy

import (
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
)

const (
	ExpectToSee       = "ExpectToSee"
	DoesntExpectToSee = "DoesntExpectToSee"
	AllowToUse        = "AllowToUse"
)

// Policy for creation container. There are 2 type of checking:
// 1) value of key from body MUST to be equal value from our csv
// 2) mustNotContain=true, value MUST not contain some value, what we don't want to see
func ComplyTheContainerPolicy(body string) (bool, string) {
	// We need get if from main.go
	file, err := os.Open("containerPolicy/container_policy.csv")
	if err != nil {
		e := fmt.Sprintf("Error opening the file: %e", err)
		return false, e
	}
	defer file.Close()

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		e := fmt.Sprintf("Error reading CSV:%e", err)
		return false, e
	}
	body = strings.ToLower(body)
	for _, row := range records {
		nameOfKey := strings.ToLower(row[0])
		valueFromCSV := strings.ToLower(row[1])
		typeOfData := row[2]
		kindOfPolicy := row[3]

		var searcher string

		switch typeOfData {
		case "slice":
			searcher = fmt.Sprintf(`"%s":\s*\[([^\]]*)\]`, nameOfKey)
		case "string":
			searcher = fmt.Sprintf(`"%s":"([^"]+)"`, nameOfKey)
		case "bool":
			searcher = fmt.Sprintf(`"%s":([^",]+)`, nameOfKey)
		}

		re := regexp.MustCompile(searcher)
		// if someone will want to add the same key for bybass
		matches := re.FindAllStringSubmatch(body, -1)
		for _, match := range matches {
			if match != nil {
				if kindOfPolicy == ExpectToSee {
					if match[1] != valueFromCSV {
						return false, nameOfKey
					}
				} else if kindOfPolicy == DoesntExpectToSee {
					csv := strings.Trim(valueFromCSV, "[]")
					values := strings.Split(csv, ",")
					for _, dontExpect := range values {
						if dontExpect == match[1] {
							return false, nameOfKey
						}
					}
				} else if kindOfPolicy == AllowToUse {
					csv := strings.Trim(valueFromCSV, "[]")
					values := strings.Split(csv, ",")

					m := strings.Split(match[1], ",")

					for _, valueOfmatch := range m {
						valueOfmatch = strings.Trim(valueOfmatch, "\"\"")
						flag := false
						for _, dontExpect := range values {
							if dontExpect == valueOfmatch {
								flag = true
								continue
							}
						}
						if !flag {
							return false, nameOfKey
						}
					}
				} else {
					log.Println("I don't know this policy!")
					return true, ""
				}
			}
		}

		// if match != nil {
		// 	if !mustNotContain {
		// 		if match[1] != value {
		// 			return false, nameOfKey
		// 		}
		// 	} else {
		// 		data := "\"" + match[1] + "\""
		// 		if strings.Contains(data, value) {
		// 			return false, nameOfKey
		// 		} else {
		// 			continue
		// 		}
		// 	}
		// }
	}
	return true, ""
}
