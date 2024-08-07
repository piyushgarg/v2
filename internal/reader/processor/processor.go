// SPDX-FileCopyrightText: Copyright The Miniflux Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package processor

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"miniflux.app/v2/internal/config"
	"miniflux.app/v2/internal/metric"
	"miniflux.app/v2/internal/model"
	"miniflux.app/v2/internal/reader/fetcher"
	"miniflux.app/v2/internal/reader/readingtime"
	"miniflux.app/v2/internal/reader/rewrite"
	"miniflux.app/v2/internal/reader/sanitizer"
	"miniflux.app/v2/internal/reader/scraper"
	"miniflux.app/v2/internal/storage"

	"github.com/PuerkitoBio/goquery"
)

var (
	youtubeRegex           = regexp.MustCompile(`youtube\.com/watch\?v=(.*)`)
	odyseeRegex            = regexp.MustCompile(`^https://odysee\.com`)
	iso8601Regex           = regexp.MustCompile(`^P((?P<year>\d+)Y)?((?P<month>\d+)M)?((?P<week>\d+)W)?((?P<day>\d+)D)?(T((?P<hour>\d+)H)?((?P<minute>\d+)M)?((?P<second>\d+)S)?)?$`)
	customReplaceRuleRegex = regexp.MustCompile(`rewrite\("(.*)"\|"(.*)"\)`)
)

// ProcessFeedEntries downloads original web page for entries and apply filters.
func ProcessFeedEntries(store *storage.Storage, feed *model.Feed, user *model.User, forceRefresh bool) {
	var filteredEntries model.Entries

	// Process older entries first
	for i := len(feed.Entries) - 1; i >= 0; i-- {
		entry := feed.Entries[i]

		slog.Debug("Processing entry",
			slog.Int64("user_id", user.ID),
			slog.Int64("entry_id", entry.ID),
			slog.String("entry_url", entry.URL),
			slog.Int64("feed_id", feed.ID),
			slog.String("feed_url", feed.FeedURL),
		)

		if isBlockedEntry(feed, entry) || !isAllowedEntry(feed, entry) {
			continue
		}

		websiteURL := getUrlFromEntry(feed, entry)
		entryIsNew := !store.EntryURLExists(feed.ID, entry.URL)
		if feed.Crawler && (entryIsNew || forceRefresh) {
			slog.Debug("Scraping entry",
				slog.Int64("user_id", user.ID),
				slog.Int64("entry_id", entry.ID),
				slog.String("entry_url", entry.URL),
				slog.Int64("feed_id", feed.ID),
				slog.String("feed_url", feed.FeedURL),
			)

			startTime := time.Now()

			requestBuilder := fetcher.NewRequestBuilder()
			requestBuilder.WithUserAgent(feed.UserAgent, config.Opts.HTTPClientUserAgent())
			requestBuilder.WithCookie(feed.Cookie)
			requestBuilder.WithTimeout(config.Opts.HTTPClientTimeout())
			requestBuilder.WithProxy(config.Opts.HTTPClientProxy())
			requestBuilder.UseProxy(feed.FetchViaProxy)
			requestBuilder.IgnoreTLSErrors(feed.AllowSelfSignedCertificates)

			content, scraperErr := scraper.ScrapeWebsite(
				requestBuilder,
				websiteURL,
				feed.ScraperRules,
			)

			if config.Opts.HasMetricsCollector() {
				status := "success"
				if scraperErr != nil {
					status = "error"
				}
				metric.ScraperRequestDuration.WithLabelValues(status).Observe(time.Since(startTime).Seconds())
			}

			if scraperErr != nil {
				slog.Warn("Unable to scrape entry",
					slog.Int64("user_id", user.ID),
					slog.Int64("entry_id", entry.ID),
					slog.String("entry_url", entry.URL),
					slog.Int64("feed_id", feed.ID),
					slog.String("feed_url", feed.FeedURL),
					slog.Any("error", scraperErr),
				)
			} else if content != "" {
				// We replace the entry content only if the scraper doesn't return any error.
				entry.Content = content
			}
		}

		rewrite.Rewriter(websiteURL, entry, feed.RewriteRules)

		// The sanitizer should always run at the end of the process to make sure unsafe HTML is filtered.
		entry.Content = sanitizer.Sanitize(websiteURL, entry.Content)

		updateEntryReadingTime(store, feed, entry, entryIsNew, user)
		filteredEntries = append(filteredEntries, entry)
	}

	feed.Entries = filteredEntries
}

func isBlockedEntry(feed *model.Feed, entry *model.Entry) bool {
	if feed.BlocklistRules != "" {
		if matchField(feed.BlocklistRules, entry.URL) || matchField(feed.BlocklistRules, entry.Title) {
			slog.Debug("Blocking entry based on rule",
				slog.Int64("entry_id", entry.ID),
				slog.String("entry_url", entry.URL),
				slog.Int64("feed_id", feed.ID),
				slog.String("feed_url", feed.FeedURL),
				slog.String("rule", feed.BlocklistRules),
			)
			return true
		}
	}

	return false
}

func isAllowedEntry(feed *model.Feed, entry *model.Entry) bool {
	if feed.KeeplistRules != "" {
		if matchField(feed.KeeplistRules, entry.URL) || matchField(feed.KeeplistRules, entry.Title) {
			slog.Debug("Allow entry based on rule",
				slog.Int64("entry_id", entry.ID),
				slog.String("entry_url", entry.URL),
				slog.Int64("feed_id", feed.ID),
				slog.String("feed_url", feed.FeedURL),
				slog.String("rule", feed.KeeplistRules),
			)
			return true
		}
		return false
	}
	return true
}

func matchField(pattern, value string) bool {
	match, err := regexp.MatchString(pattern, value)
	if err != nil {
		slog.Debug("Failed on regexp match",
			slog.String("pattern", pattern),
			slog.String("value", value),
			slog.Bool("match", match),
			slog.Any("error", err),
		)
	}
	return match
}

// ProcessEntryWebPage downloads the entry web page and apply rewrite rules.
func ProcessEntryWebPage(feed *model.Feed, entry *model.Entry, user *model.User) error {
	startTime := time.Now()
	websiteURL := getUrlFromEntry(feed, entry)

	requestBuilder := fetcher.NewRequestBuilder()
	requestBuilder.WithUserAgent(feed.UserAgent, config.Opts.HTTPClientUserAgent())
	requestBuilder.WithCookie(feed.Cookie)
	requestBuilder.WithTimeout(config.Opts.HTTPClientTimeout())
	requestBuilder.WithProxy(config.Opts.HTTPClientProxy())
	requestBuilder.UseProxy(feed.FetchViaProxy)
	requestBuilder.IgnoreTLSErrors(feed.AllowSelfSignedCertificates)

	content, scraperErr := scraper.ScrapeWebsite(
		requestBuilder,
		websiteURL,
		feed.ScraperRules,
	)

	if config.Opts.HasMetricsCollector() {
		status := "success"
		if scraperErr != nil {
			status = "error"
		}
		metric.ScraperRequestDuration.WithLabelValues(status).Observe(time.Since(startTime).Seconds())
	}

	if scraperErr != nil {
		return scraperErr
	}

	if content != "" {
		entry.Content = content
		entry.ReadingTime = readingtime.EstimateReadingTime(entry.Content, user.DefaultReadingSpeed, user.CJKReadingSpeed)
	}

	rewrite.Rewriter(websiteURL, entry, entry.Feed.RewriteRules)
	entry.Content = sanitizer.Sanitize(websiteURL, entry.Content)

	return nil
}

func getUrlFromEntry(feed *model.Feed, entry *model.Entry) string {
	var url = entry.URL
	if feed.UrlRewriteRules != "" {
		parts := customReplaceRuleRegex.FindStringSubmatch(feed.UrlRewriteRules)

		if len(parts) >= 3 {
			// re := regexp.MustCompile(parts[1])
			// url = re.ReplaceAllString(entry.URL, parts[2])
			url = rewriteUrl(entry.URL)
			fmt.Printf("\n%s\t==>\t%s\n", entry.URL, url)
			// replace the previous entry url. only then the updated entry url will be updated.
			entry.URL = url
			slog.Debug("Rewriting entry URL",
				slog.Int64("entry_id", entry.ID),
				slog.String("original_entry_url", entry.URL),
				slog.String("rewritten_entry_url", url),
				slog.Int64("feed_id", feed.ID),
				slog.String("feed_url", feed.FeedURL),
			)
		} else {
			slog.Debug("Cannot find search and replace terms for replace rule",
				slog.Int64("entry_id", entry.ID),
				slog.String("original_entry_url", entry.URL),
				slog.String("rewritten_entry_url", url),
				slog.Int64("feed_id", feed.ID),
				slog.String("feed_url", feed.FeedURL),
				slog.String("url_rewrite_rules", feed.UrlRewriteRules),
			)
		}
	}
	return url
}

func rewriteUrl(article string) string {
	//fmt.Println("this is working fine")
	// https://news.google.com/rss/articles/CCAiC2lzaU4zUVBSUDY0mAEB?oc=5
	// https://news.google.com/rss/articles/CBMiU2h0dHBzOi8vd3d3Lndhc2hpbmd0b25wb3N0LmNvbS93b3JsZC8yMDIzLzA0LzIzL2Jha2htdXQtZGVzdHJveWVkLWNpdHktdWtyYWluZS13YXIv0gEA?oc=5
	//article := "https://news.google.com/rss/articles/CCAiC2lzaU4zUVBSUDY0mAEB?oc=5"
	//article := "https://news.google.com/rss/articles/CBMiU2h0dHBzOi8vd3d3Lndhc2hpbmd0b25wb3N0LmNvbS93b3JsZC8yMDIzLzA0LzIzL2Jha2htdXQtZGVzdHJveWVkLWNpdHktdWtyYWluZS13YXIv0gEA?oc=5"
	//article := "https://news.google.com/rss/articles/CBMiekFVX3lxTE00ZVNTRGhZeXQxTXMwMlNlbEQyUXFlck1LMmNtSGVSSlJHdEV0SUFkcHpvMnEtLUoxZ0lrSEZoSVdIRVBhSGZuLUNXZnQ5QjVHdWRkUjFfR29MY3MzWmthR1loanFBcjJHNEVsUGxrX1JZdDVGZnQ2cDZR0gF_QVVfeXFMTmg1YVExdDNIejI5RXBTalVpa0hCeGh4Wl9MX2VfOUdzTVBfQWJQZk9CajB1cG95ZUREV2FIb25aek9GMWxESFdjajk3UktJOFliZlhncE53NEtxcWd1ckFNaU9TeE5aVG9kbTRONVo0MHQyMHlRUVVqbjlrNWVZRQ?oc=5"
	//expr := regexp.MustCompile("(https.*google[.]com.*/)([a-z0-9A-Z_]*)(\\?.*)")
	//match := expr.FindStringSubmatch(article)
	base64str := ""
	/*if len(match) > 3 {
		base64str = match[2]
	}*/

	uri, err := url.ParseRequestURI(article)
	if err != nil {
		fmt.Printf("\n%s", err)
	} else {
		fmt.Printf("\n%s", uri.Path)
		after, found := strings.CutPrefix(uri.Path, "/rss/articles/")
		if found {
			base64str = after
		}
	}

	if base64str != "" {
		//fmt.Printf("\nbase64 %s", base64str)
		data, err := base64.StdEncoding.DecodeString(base64str)
		if err != nil {
			fmt.Printf("%s\n", err)
			link := fetchLink(base64str)
			if link == "" {
				return article
			} else {
				return link
			}
		}

		datalength := len(data)
		if datalength > 5 && data[0] == 8 && data[1] == 19 && data[2] == 34 {
			data = data[3:]
			//fmt.Printf("\n%q\n", string(data))
		}

		datalength = len(data)
		if datalength > 5 && data[datalength-3] == 210 && data[datalength-2] == 1 && data[datalength-1] == 0 {
			data = data[:datalength-3]
			//fmt.Printf("\n%q\n", string(data))
		}

		datalength = len(data)
		if datalength > 5 && data[0] == 8 && data[1] == 32 && data[2] == 34 {
			data = data[3:]
			//fmt.Printf("\n%q\n", string(data))
		}

		datalength = len(data)
		if datalength > 5 && data[datalength-3] == 152 && data[datalength-2] == 1 && data[datalength-1] == 1 {
			data = data[:datalength-3]
			//fmt.Printf("\n%q\n", string(data))
		}

		length := data[0]
		if length == 11 {
			data = data[1:]
			return "https://youtu.be/" + string(data[1:])
		} else if length > 128 {
			data = data[2:]
		} else {
			data = data[1:]
		}
		if string(data[0:6]) == "AU_yqL" {
			link := fetchLink(base64str)
			if link == "" {
				return article
			} else {
				return link
			}
		} else {
			return string(data)
		}

		/*if j > 0 && k > j {
			//fmt.Printf("\nj-%d k-%d", j, k)
			baseYoutube := ""
			if len(data[j:k]) < 15 {
				baseYoutube = "https://youtube.com/watch?v="
			}
			baseYoutube += string(data[j:k])
			article = baseYoutube

			//fmt.Printf("\nlength %d", len(baseYoutube))
			//fmt.Printf("\nfinal url %s", baseYoutube)
		}*/
	}
	return article
}

func fetchLink(id string) string {
	_url := "https://news.google.com/_/DotsSplashUi/data/batchexecute?rpcids=Fbv4je"
	method := "POST"
	s := "[[[\"Fbv4je\",\"[\\\"garturlreq\\\",[[\\\"en-US\\\",\\\"US\\\",[\\\"FINANCE_TOP_INDICES\\\",\\\"WEB_TEST_1_0_0\\\"],null,null,1,1,\\\"US:en\\\",null,180,null,null,null,null,null,0,null,null,[1608992183,723341000]],\\\"en-US\\\",\\\"US\\\",1,[2,3,4,8],1,0,\\\"655000234\\\",0,0,null,0],\\\"" + id + "\\\"]\",null,\"generic\"]]]"
	escapeError := url.QueryEscape(s)
	//fmt.Printf("\nescaped url %s", escapeError)

	payload := strings.NewReader("f.req=" + escapeError)

	// %5B%5B%5B%22Fbv4je%22%2C%22%5B%5C%22garturlreq%5C%22%2C%5B%5B%5C%22en-US%5C%22%2C%5C%22US%5C%22%2C%5B%5C%22FINANCE_TOP_INDICES%5C%22%2C%5C%22WEB_TEST_1_0_0%5C%22%5D%2Cnull%2Cnull%2C1%2C1%2C%5C%22US%3Aen%5C%22%2Cnull%2C180%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2C0%2Cnull%2Cnull%2C%5B1608992183%2C723341000%5D%5D%2C%5C%22en-US%5C%22%2C%5C%22US%5C%22%2C1%2C%5B2%2C3%2C4%2C8%5D%2C1%2C0%2C%5C%22655000234%5C%22%2C0%2C0%2Cnull%2C0%5D%2C%5C%22CBMiekFVX3lxTE00ZVNTRGhZeXQxTXMwMlNlbEQyUXFlck1LMmNtSGVSSlJHdEV0SUFkcHpvMnEtLUoxZ0lrSEZoSVdIRVBhSGZuLUNXZnQ5QjVHdWRkUjFfR29MY3MzWmthR1loanFBcjJHNEVsUGxrX1JZdDVGZnQ2cDZR0gF_QVVfeXFMTmg1YVExdDNIejI5RXBTalVpa0hCeGh4Wl9MX2VfOUdzTVBfQWJQZk9CajB1cG95ZUREV2FIb25aek9GMWxESFdjajk3UktJOFliZlhncE53NEtxcWd1ckFNaU9TeE5aVG9kbTRONVo0MHQyMHlRUVVqbjlrNWVZRQ%5C%22%5D%22%2Cnull%2C%22generic%22%5D%5D%5D
	client := &http.Client{}
	req, err := http.NewRequest(method, _url, payload)

	if err != nil {
		fmt.Println(err)
		return ""
	}
	req.Header.Add("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0")
	req.Header.Add("Referer", "https://news.google.com/")
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	res, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return ""
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		fmt.Println(err)
		return ""
	}
	// https://regex101.com/r/NUS0sn/1
	expr := regexp.MustCompile("(https?:[^\"\\\\]*)")
	match := expr.FindStringSubmatch(string(body))
	if len(match) > 0 {
		return match[0]
	}
	fmt.Println(string(body))
	return ""
}

func updateEntryReadingTime(store *storage.Storage, feed *model.Feed, entry *model.Entry, entryIsNew bool, user *model.User) {
	if shouldFetchYouTubeWatchTime(entry) {
		if entryIsNew {
			watchTime, err := fetchYouTubeWatchTime(entry.URL)
			if err != nil {
				slog.Warn("Unable to fetch YouTube watch time",
					slog.Int64("user_id", user.ID),
					slog.Int64("entry_id", entry.ID),
					slog.String("entry_url", entry.URL),
					slog.Int64("feed_id", feed.ID),
					slog.String("feed_url", feed.FeedURL),
					slog.Any("error", err),
				)
			}
			entry.ReadingTime = watchTime
		} else {
			entry.ReadingTime = store.GetReadTime(entry, feed)
		}
	}

	if shouldFetchOdyseeWatchTime(entry) {
		if entryIsNew {
			watchTime, err := fetchOdyseeWatchTime(entry.URL)
			if err != nil {
				slog.Warn("Unable to fetch Odysee watch time",
					slog.Int64("user_id", user.ID),
					slog.Int64("entry_id", entry.ID),
					slog.String("entry_url", entry.URL),
					slog.Int64("feed_id", feed.ID),
					slog.String("feed_url", feed.FeedURL),
					slog.Any("error", err),
				)
			}
			entry.ReadingTime = watchTime
		} else {
			entry.ReadingTime = store.GetReadTime(entry, feed)
		}
	}
	// Handle YT error case and non-YT entries.
	if entry.ReadingTime == 0 {
		entry.ReadingTime = readingtime.EstimateReadingTime(entry.Content, user.DefaultReadingSpeed, user.CJKReadingSpeed)
	}
}

func shouldFetchYouTubeWatchTime(entry *model.Entry) bool {
	if !config.Opts.FetchYouTubeWatchTime() {
		return false
	}
	matches := youtubeRegex.FindStringSubmatch(entry.URL)
	urlMatchesYouTubePattern := len(matches) == 2
	return urlMatchesYouTubePattern
}

func shouldFetchOdyseeWatchTime(entry *model.Entry) bool {
	if !config.Opts.FetchOdyseeWatchTime() {
		return false
	}
	matches := odyseeRegex.FindStringSubmatch(entry.URL)
	return matches != nil
}

func fetchYouTubeWatchTime(websiteURL string) (int, error) {
	requestBuilder := fetcher.NewRequestBuilder()
	requestBuilder.WithTimeout(config.Opts.HTTPClientTimeout())
	requestBuilder.WithProxy(config.Opts.HTTPClientProxy())

	responseHandler := fetcher.NewResponseHandler(requestBuilder.ExecuteRequest(websiteURL))
	defer responseHandler.Close()

	if localizedError := responseHandler.LocalizedError(); localizedError != nil {
		slog.Warn("Unable to fetch YouTube page", slog.String("website_url", websiteURL), slog.Any("error", localizedError.Error()))
		return 0, localizedError.Error()
	}

	doc, docErr := goquery.NewDocumentFromReader(responseHandler.Body(config.Opts.HTTPClientMaxBodySize()))
	if docErr != nil {
		return 0, docErr
	}

	durs, exists := doc.Find(`meta[itemprop="duration"]`).First().Attr("content")
	if !exists {
		return 0, errors.New("duration has not found")
	}

	dur, err := parseISO8601(durs)
	if err != nil {
		return 0, fmt.Errorf("unable to parse duration %s: %v", durs, err)
	}

	return int(dur.Minutes()), nil
}

func fetchOdyseeWatchTime(websiteURL string) (int, error) {
	requestBuilder := fetcher.NewRequestBuilder()
	requestBuilder.WithTimeout(config.Opts.HTTPClientTimeout())
	requestBuilder.WithProxy(config.Opts.HTTPClientProxy())

	responseHandler := fetcher.NewResponseHandler(requestBuilder.ExecuteRequest(websiteURL))
	defer responseHandler.Close()

	if localizedError := responseHandler.LocalizedError(); localizedError != nil {
		slog.Warn("Unable to fetch Odysee watch time", slog.String("website_url", websiteURL), slog.Any("error", localizedError.Error()))
		return 0, localizedError.Error()
	}

	doc, docErr := goquery.NewDocumentFromReader(responseHandler.Body(config.Opts.HTTPClientMaxBodySize()))
	if docErr != nil {
		return 0, docErr
	}

	durs, exists := doc.Find(`meta[property="og:video:duration"]`).First().Attr("content")
	// durs contains video watch time in seconds
	if !exists {
		return 0, errors.New("duration has not found")
	}

	dur, err := strconv.ParseInt(durs, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("unable to parse duration %s: %v", durs, err)
	}

	return int(dur / 60), nil
}

// parseISO8601 parses an ISO 8601 duration string.
func parseISO8601(from string) (time.Duration, error) {
	var match []string
	var d time.Duration

	if iso8601Regex.MatchString(from) {
		match = iso8601Regex.FindStringSubmatch(from)
	} else {
		return 0, errors.New("could not parse duration string")
	}

	for i, name := range iso8601Regex.SubexpNames() {
		part := match[i]
		if i == 0 || name == "" || part == "" {
			continue
		}

		val, err := strconv.ParseInt(part, 10, 64)
		if err != nil {
			return 0, err
		}

		switch name {
		case "hour":
			d = d + (time.Duration(val) * time.Hour)
		case "minute":
			d = d + (time.Duration(val) * time.Minute)
		case "second":
			d = d + (time.Duration(val) * time.Second)
		default:
			return 0, fmt.Errorf("unknown field %s", name)
		}
	}

	return d, nil
}
