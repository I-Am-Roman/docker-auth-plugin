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
	PathToThePolicy   = "containerPolicy/container_policy.csv"
)

// Policy for creation container. There are 3 type of checking:
// 1) DoesntExpectToSee, if some of valueFromBody == valueFromPolitic - DENY
// 2) AllowToUse, if some of valueFromBody != valueFromPolitic - DENY
// 3) ExpectToSee, if valueFromBody != valueFromPolitic - DENY
func ComplyTheContainerPolicy(body string) (bool, string) {
	file, err := os.Open(PathToThePolicy)
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
			// will ignore null and []
			searcher = fmt.Sprintf(`"%s":\s*\[([^\]]*)\]`, nameOfKey)
		case "string":
			// will ignore null
			searcher = fmt.Sprintf(`"%s":"([^"]+)"`, nameOfKey)
		case "bool":
			searcher = fmt.Sprintf(`"%s":([^",]+)`, nameOfKey)
		}

		re := regexp.MustCompile(searcher)
		// if someone will want to add the same key with a forbidden value for bybass
		matches := re.FindAllStringSubmatch(body, -1)
		for _, match := range matches {
			if match != nil {
				if kindOfPolicy == ExpectToSee {
					if match[1] != valueFromCSV {
						return false, nameOfKey
					}
				} else if kindOfPolicy == DoesntExpectToSee {
					csv := strings.Trim(valueFromCSV, "[]")
					sliceFromCSV := strings.Split(csv, ",")
					// if will get: ["value1","value2","value3"]
					// regexpr give us at match[1] - "value1","value2","value3"
					// we should check every single value
					valueOfMatches := strings.Split(match[1], ",")

					for _, valueOfMatch := range valueOfMatches {
						valueOfMatch := strings.Trim(valueOfMatch, "\"")
						for _, dontExpect := range sliceFromCSV {
							if dontExpect == valueOfMatch {
								return false, nameOfKey
							}
						}
					}
				} else if kindOfPolicy == AllowToUse {
					csv := strings.Trim(valueFromCSV, "[]")
					sliceFromCSV := strings.Split(csv, ",")
					valueOfMatches := strings.Split(match[1], ",")

					for _, valueOfMatch := range valueOfMatches {
						valueOfMatch = strings.Trim(valueOfMatch, "\"")
						isItValueOK := false
						for _, allowToUse := range sliceFromCSV {
							if allowToUse == valueOfMatch {
								isItValueOK = true
								continue
							}
						}
						if !isItValueOK {
							return false, nameOfKey
						}
					}
				} else {
					log.Println("I don't know this policy!")
					return true, ""
				}
			}
		}
	}
	return true, ""
}
