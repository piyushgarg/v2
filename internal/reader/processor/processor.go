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
	"slices"
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
	"miniflux.app/v2/internal/reader/urlcleaner"
	"miniflux.app/v2/internal/storage"

	"github.com/PuerkitoBio/goquery"
	"github.com/tdewolff/minify/v2"
	"github.com/tdewolff/minify/v2/html"
)

var (
	youtubeRegex           = regexp.MustCompile(`youtube\.com/watch\?v=(.*)$`)
	nebulaRegex            = regexp.MustCompile(`^https://nebula\.tv`)
	odyseeRegex            = regexp.MustCompile(`^https://odysee\.com`)
	bilibiliRegex          = regexp.MustCompile(`bilibili\.com/video/(.*)$`)
	timelengthRegex        = regexp.MustCompile(`"timelength":\s*(\d+)`)
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
			slog.String("entry_url", entry.URL),
			slog.String("entry_hash", entry.Hash),
			slog.String("entry_title", entry.Title),
			slog.Int64("feed_id", feed.ID),
			slog.String("feed_url", feed.FeedURL),
		)
		if isBlockedEntry(feed, entry, user) || !isAllowedEntry(feed, entry, user) || !isRecentEntry(entry) {
			continue
		}

		if cleanedURL, err := urlcleaner.RemoveTrackingParameters(entry.URL); err == nil {
			entry.URL = cleanedURL
		}

		pageBaseURL := ""
		rewrittenURL := rewriteEntryURL(feed, entry)
		entryIsNew := store.IsNewEntry(feed.ID, entry.Hash)
		if feed.Crawler && (entryIsNew || forceRefresh) {
			slog.Debug("Scraping entry",
				slog.Int64("user_id", user.ID),
				slog.String("entry_url", entry.URL),
				slog.String("entry_hash", entry.Hash),
				slog.String("entry_title", entry.Title),
				slog.Int64("feed_id", feed.ID),
				slog.String("feed_url", feed.FeedURL),
				slog.Bool("entry_is_new", entryIsNew),
				slog.Bool("force_refresh", forceRefresh),
				slog.String("rewritten_url", rewrittenURL),
			)

			startTime := time.Now()

			requestBuilder := fetcher.NewRequestBuilder()
			requestBuilder.WithUserAgent(feed.UserAgent, config.Opts.HTTPClientUserAgent())
			requestBuilder.WithCookie(feed.Cookie)
			requestBuilder.WithTimeout(config.Opts.HTTPClientTimeout())
			requestBuilder.WithProxy(config.Opts.HTTPClientProxy())
			requestBuilder.UseProxy(feed.FetchViaProxy)
			requestBuilder.IgnoreTLSErrors(feed.AllowSelfSignedCertificates)
			requestBuilder.DisableHTTP2(feed.DisableHTTP2)

			scrapedPageBaseURL, extractedContent, scraperErr := scraper.ScrapeWebsite(
				requestBuilder,
				rewrittenURL,
				feed.ScraperRules,
			)

			if scrapedPageBaseURL != "" {
				pageBaseURL = scrapedPageBaseURL
			}

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
					slog.String("entry_url", entry.URL),
					slog.Int64("feed_id", feed.ID),
					slog.String("feed_url", feed.FeedURL),
					slog.Any("error", scraperErr),
				)
			} else if extractedContent != "" {
				// We replace the entry content only if the scraper doesn't return any error.
				entry.Content = minifyEntryContent(extractedContent)
			}
		}

		rewrite.Rewriter(rewrittenURL, entry, feed.RewriteRules)

		if pageBaseURL == "" {
			pageBaseURL = rewrittenURL
		}

		// The sanitizer should always run at the end of the process to make sure unsafe HTML is filtered out.
		entry.Content = sanitizer.Sanitize(pageBaseURL, entry.Content)

		updateEntryReadingTime(store, feed, entry, entryIsNew, user)
		filteredEntries = append(filteredEntries, entry)
	}

	feed.Entries = filteredEntries
}

func isBlockedEntry(feed *model.Feed, entry *model.Entry, user *model.User) bool {
	if user.BlockFilterEntryRules != "" {
		rules := strings.Split(user.BlockFilterEntryRules, "\n")
		for _, rule := range rules {
			parts := strings.SplitN(rule, "=", 2)

			var match bool
			switch parts[0] {
			case "EntryTitle":
				match, _ = regexp.MatchString(parts[1], entry.Title)
			case "EntryURL":
				match, _ = regexp.MatchString(parts[1], entry.URL)
			case "EntryCommentsURL":
				match, _ = regexp.MatchString(parts[1], entry.CommentsURL)
			case "EntryContent":
				match, _ = regexp.MatchString(parts[1], entry.Content)
			case "EntryAuthor":
				match, _ = regexp.MatchString(parts[1], entry.Author)
			case "EntryTag":
				containsTag := slices.ContainsFunc(entry.Tags, func(tag string) bool {
					match, _ = regexp.MatchString(parts[1], tag)
					return match
				})
				if containsTag {
					match = true
				}
			}

			if match {
				slog.Debug("Blocking entry based on rule",
					slog.String("entry_url", entry.URL),
					slog.Int64("feed_id", feed.ID),
					slog.String("feed_url", feed.FeedURL),
					slog.String("rule", rule),
				)
				return true
			}
		}
	}

	if feed.BlocklistRules == "" {
		return false
	}

	compiledBlocklist, err := regexp.Compile(feed.BlocklistRules)
	if err != nil {
		slog.Debug("Failed on regexp compilation",
			slog.String("pattern", feed.BlocklistRules),
			slog.Any("error", err),
		)
		return false
	}

	containsBlockedTag := slices.ContainsFunc(entry.Tags, func(tag string) bool {
		return compiledBlocklist.MatchString(tag)
	})

	if compiledBlocklist.MatchString(entry.URL) || compiledBlocklist.MatchString(entry.Title) || compiledBlocklist.MatchString(entry.Author) || containsBlockedTag {
		slog.Debug("Blocking entry based on rule",
			slog.String("entry_url", entry.URL),
			slog.Int64("feed_id", feed.ID),
			slog.String("feed_url", feed.FeedURL),
			slog.String("rule", feed.BlocklistRules),
		)
		return true
	}

	return false
}

func isAllowedEntry(feed *model.Feed, entry *model.Entry, user *model.User) bool {
	if user.KeepFilterEntryRules != "" {
		rules := strings.Split(user.KeepFilterEntryRules, "\n")
		for _, rule := range rules {
			parts := strings.SplitN(rule, "=", 2)

			var match bool
			switch parts[0] {
			case "EntryTitle":
				match, _ = regexp.MatchString(parts[1], entry.Title)
			case "EntryURL":
				match, _ = regexp.MatchString(parts[1], entry.URL)
			case "EntryCommentsURL":
				match, _ = regexp.MatchString(parts[1], entry.CommentsURL)
			case "EntryContent":
				match, _ = regexp.MatchString(parts[1], entry.Content)
			case "EntryAuthor":
				match, _ = regexp.MatchString(parts[1], entry.Author)
			case "EntryTag":
				containsTag := slices.ContainsFunc(entry.Tags, func(tag string) bool {
					match, _ = regexp.MatchString(parts[1], tag)
					return match
				})
				if containsTag {
					match = true
				}
			}

			if match {
				slog.Debug("Allowing entry based on rule",
					slog.String("entry_url", entry.URL),
					slog.Int64("feed_id", feed.ID),
					slog.String("feed_url", feed.FeedURL),
					slog.String("rule", rule),
				)
				return true
			}
		}
		return false
	}

	if feed.KeeplistRules == "" {
		return true
	}

	compiledKeeplist, err := regexp.Compile(feed.KeeplistRules)
	if err != nil {
		slog.Debug("Failed on regexp compilation",
			slog.String("pattern", feed.KeeplistRules),
			slog.Any("error", err),
		)
		return false
	}
	containsAllowedTag := slices.ContainsFunc(entry.Tags, func(tag string) bool {
		return compiledKeeplist.MatchString(tag)
	})

	if compiledKeeplist.MatchString(entry.URL) || compiledKeeplist.MatchString(entry.Title) || compiledKeeplist.MatchString(entry.Author) || containsAllowedTag {
		slog.Debug("Allow entry based on rule",
			slog.String("entry_url", entry.URL),
			slog.Int64("feed_id", feed.ID),
			slog.String("feed_url", feed.FeedURL),
			slog.String("rule", feed.KeeplistRules),
		)
		return true
	}
	return false
}

// ProcessEntryWebPage downloads the entry web page and apply rewrite rules.
func ProcessEntryWebPage(feed *model.Feed, entry *model.Entry, user *model.User) error {
	startTime := time.Now()
	rewrittenEntryURL := rewriteEntryURL(feed, entry)

	requestBuilder := fetcher.NewRequestBuilder()
	requestBuilder.WithUserAgent(feed.UserAgent, config.Opts.HTTPClientUserAgent())
	requestBuilder.WithCookie(feed.Cookie)
	requestBuilder.WithTimeout(config.Opts.HTTPClientTimeout())
	requestBuilder.WithProxy(config.Opts.HTTPClientProxy())
	requestBuilder.UseProxy(feed.FetchViaProxy)
	requestBuilder.IgnoreTLSErrors(feed.AllowSelfSignedCertificates)
	requestBuilder.DisableHTTP2(feed.DisableHTTP2)

	pageBaseURL, extractedContent, scraperErr := scraper.ScrapeWebsite(
		requestBuilder,
		rewrittenEntryURL,
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

	if extractedContent != "" {
		entry.Content = minifyEntryContent(extractedContent)
		if user.ShowReadingTime {
			entry.ReadingTime = readingtime.EstimateReadingTime(entry.Content, user.DefaultReadingSpeed, user.CJKReadingSpeed)
		}
	}

	rewrite.Rewriter(rewrittenEntryURL, entry, entry.Feed.RewriteRules)
	entry.Content = sanitizer.Sanitize(pageBaseURL, entry.Content)

	return nil
}

func rewriteEntryURL(feed *model.Feed, entry *model.Entry) string {
	var rewrittenURL = entry.URL
	if feed.UrlRewriteRules != "" {
		parts := customReplaceRuleRegex.FindStringSubmatch(feed.UrlRewriteRules)

		if len(parts) >= 3 {
			/*re, err := regexp.Compile(parts[1])
			if err != nil {
				slog.Error("Failed on regexp compilation",
					slog.String("url_rewrite_rules", feed.UrlRewriteRules),
					slog.Any("error", err),
				)
				return rewrittenURL
			}
			rewrittenURL = re.ReplaceAllString(entry.URL, parts[2])*/
			rewrittenURL = rewriteUrl(entry.URL)
			fmt.Printf("\n%s\t==>\t%s\n", entry.URL, rewrittenURL)
			// replace the previous entry url. only then the updated entry url will be updated.
			entry.URL = rewrittenURL
			slog.Debug("Rewriting entry URL",
				slog.String("original_entry_url", entry.URL),
				slog.String("rewritten_entry_url", rewrittenURL),
				slog.Int64("feed_id", feed.ID),
				slog.String("feed_url", feed.FeedURL),
			)
		} else {
			slog.Debug("Cannot find search and replace terms for replace rule",
				slog.String("original_entry_url", entry.URL),
				slog.String("rewritten_entry_url", rewrittenURL),
				slog.Int64("feed_id", feed.ID),
				slog.String("feed_url", feed.FeedURL),
				slog.String("url_rewrite_rules", feed.UrlRewriteRules),
			)
		}
	}

	return rewrittenURL
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
			link := fetchLinkNewDecoder(base64str)
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
		} else if length >= 128 {
			data = data[2:]
		} else {
			data = data[1:]
		}
		if string(data[0:6]) == "AU_yqL" {
			link := fetchLinkNewDecoder(base64str)
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

func fetchTimeStampAndSignature(id string) (string, string) {

	ts := ""
	sig := ""
	_url := "https://news.google.com/articles/" + id
	method := "GET"
	client := &http.Client{}
	req, err := http.NewRequest(method, _url, nil)

	if err != nil {
		fmt.Println(err)
		return ts, sig
	}
	req.Header.Add("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0")
	req.Header.Add("Referer", "https://news.google.com/")
	res, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return ts, sig
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		fmt.Println(err)
		return ts, sig
	}
	//fmt.Println(string(body))
	expr := regexp.MustCompile("data-n-a-ts=\"([^\"]*)\"")
	match := expr.FindStringSubmatch(string(body))
	if len(match) > 0 {
		ts = match[1]
	}
	//fmt.Println(ts)
	expr = regexp.MustCompile("data-n-a-sg=\"([^\"]*)\"")
	match = expr.FindStringSubmatch(string(body))
	if len(match) > 0 {
		sig = match[1]
	}
	//fmt.Println(sig)
	return ts, sig

}

func fetchLinkNewDecoder(id string) string {
	ts, sig := fetchTimeStampAndSignature(id)
	fmt.Println(ts)
	fmt.Println(sig)
	if ts == "" || sig == "" {
		slog.Error("unable to fetch ts or sig")
		return ""
	}

	_url := "https://news.google.com/_/DotsSplashUi/data/batchexecute"
	method := "POST"
	s := "[[[\"Fbv4je\", \"[\\\"garturlreq\\\",[[\\\"X\\\",\\\"X\\\",[\\\"X\\\",\\\"X\\\"],null,null,1,1,\\\"US:en\\\",null,1,null,null,null,null,null,0,1],\\\"X\\\",\\\"X\\\",1,[1,1,1],1,1,null,0,0,null,0],\\\"" + id + "\\\"," + ts + ",\\\"" + sig + "\\\"]\"]]]"
	escapeError := url.QueryEscape(s)
	fmt.Printf("\nescaped url %s", escapeError)

	payload := strings.NewReader("f.req=" + escapeError)

	// %5B%5B%5B%22Fbv4je%22%2C%22%5B%5C%22garturlreq%5C%22%2C%5B%5B%5C%22en-US%5C%22%2C%5C%22US%5C%22%2C%5B%5C%22FINANCE_TOP_INDICES%5C%22%2C%5C%22WEB_TEST_1_0_0%5C%22%5D%2Cnull%2Cnull%2C1%2C1%2C%5C%22US%3Aen%5C%22%2Cnull%2C180%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2C0%2Cnull%2Cnull%2C%5B1608992183%2C723341000%5D%5D%2C%5C%22en-US%5C%22%2C%5C%22US%5C%22%2C1%2C%5B2%2C3%2C4%2C8%5D%2C1%2C0%2C%5C%22655000234%5C%22%2C0%2C0%2Cnull%2C0%5D%2C%5C%22CBMiekFVX3lxTE00ZVNTRGhZeXQxTXMwMlNlbEQyUXFlck1LMmNtSGVSSlJHdEV0SUFkcHpvMnEtLUoxZ0lrSEZoSVdIRVBhSGZuLUNXZnQ5QjVHdWRkUjFfR29MY3MzWmthR1loanFBcjJHNEVsUGxrX1JZdDVGZnQ2cDZR0gF_QVVfeXFMTmg1YVExdDNIejI5RXBTalVpa0hCeGh4Wl9MX2VfOUdzTVBfQWJQZk9CajB1cG95ZUREV2FIb25aek9GMWxESFdjajk3UktJOFliZlhncE53NEtxcWd1ckFNaU9TeE5aVG9kbTRONVo0MHQyMHlRUVVqbjlrNWVZRQ%5C%22%5D%22%2Cnull%2C%22generic%22%5D%5D%5D
	client := &http.Client{}
	req, err := http.NewRequest(method, _url, payload)

	if err != nil {
		fmt.Println(err)
		return ""
	}
	req.Header.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36")
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
	expr := regexp.MustCompile("(https?:[^,]*)(\\\\\")")
	match := expr.FindStringSubmatch(string(body))
	if len(match) > 0 {
		match[1] = strings.ReplaceAll(match[1], "\\\\", "\\")
		unquote, err := strconv.Unquote("\"" + match[1] + "\"")
		if err != nil {
			return ""
		}
		return unquote
	}
	fmt.Println(string(body))
	return ""
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
	expr := regexp.MustCompile("(https?:[^,]*)(\\\\\")")
	match := expr.FindStringSubmatch(string(body))
	if len(match) > 0 {
		match[1] = strings.ReplaceAll(match[1], "\\\\", "\\")
		unquote, err := strconv.Unquote("\"" + match[1] + "\"")
		if err != nil {
			return ""
		}
		return unquote
	}
	fmt.Println(string(body))
	return ""
}

func updateEntryReadingTime(store *storage.Storage, feed *model.Feed, entry *model.Entry, entryIsNew bool, user *model.User) {
	if !user.ShowReadingTime {
		slog.Debug("Skip reading time estimation for this user", slog.Int64("user_id", user.ID))
		return
	}

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
			entry.ReadingTime = store.GetReadTime(feed.ID, entry.Hash)
		}
	}

	if shouldFetchNebulaWatchTime(entry) {
		if entryIsNew {
			watchTime, err := fetchNebulaWatchTime(entry.URL)
			if err != nil {
				slog.Warn("Unable to fetch Nebula watch time",
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
			entry.ReadingTime = store.GetReadTime(feed.ID, entry.Hash)
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
			entry.ReadingTime = store.GetReadTime(feed.ID, entry.Hash)
		}
	}

	if shouldFetchBilibiliWatchTime(entry) {
		if entryIsNew {
			watchTime, err := fetchBilibiliWatchTime(entry.URL)
			if err != nil {
				slog.Warn("Unable to fetch Bilibili watch time",
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
			entry.ReadingTime = store.GetReadTime(feed.ID, entry.Hash)
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

func shouldFetchNebulaWatchTime(entry *model.Entry) bool {
	if !config.Opts.FetchNebulaWatchTime() {
		return false
	}
	matches := nebulaRegex.FindStringSubmatch(entry.URL)
	return matches != nil
}

func shouldFetchOdyseeWatchTime(entry *model.Entry) bool {
	if !config.Opts.FetchOdyseeWatchTime() {
		return false
	}
	matches := odyseeRegex.FindStringSubmatch(entry.URL)
	return matches != nil
}

func shouldFetchBilibiliWatchTime(entry *model.Entry) bool {
	if !config.Opts.FetchBilibiliWatchTime() {
		return false
	}
	matches := bilibiliRegex.FindStringSubmatch(entry.URL)
	urlMatchesBilibiliPattern := len(matches) == 2
	return urlMatchesBilibiliPattern
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

func fetchNebulaWatchTime(websiteURL string) (int, error) {
	requestBuilder := fetcher.NewRequestBuilder()
	requestBuilder.WithTimeout(config.Opts.HTTPClientTimeout())
	requestBuilder.WithProxy(config.Opts.HTTPClientProxy())

	responseHandler := fetcher.NewResponseHandler(requestBuilder.ExecuteRequest(websiteURL))
	defer responseHandler.Close()

	if localizedError := responseHandler.LocalizedError(); localizedError != nil {
		slog.Warn("Unable to fetch Nebula watch time", slog.String("website_url", websiteURL), slog.Any("error", localizedError.Error()))
		return 0, localizedError.Error()
	}

	doc, docErr := goquery.NewDocumentFromReader(responseHandler.Body(config.Opts.HTTPClientMaxBodySize()))
	if docErr != nil {
		return 0, docErr
	}

	durs, exists := doc.Find(`meta[property="video:duration"]`).First().Attr("content")
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

func fetchBilibiliWatchTime(websiteURL string) (int, error) {
	requestBuilder := fetcher.NewRequestBuilder()
	requestBuilder.WithTimeout(config.Opts.HTTPClientTimeout())
	requestBuilder.WithProxy(config.Opts.HTTPClientProxy())

	responseHandler := fetcher.NewResponseHandler(requestBuilder.ExecuteRequest(websiteURL))
	defer responseHandler.Close()

	if localizedError := responseHandler.LocalizedError(); localizedError != nil {
		slog.Warn("Unable to fetch Bilibili page", slog.String("website_url", websiteURL), slog.Any("error", localizedError.Error()))
		return 0, localizedError.Error()
	}

	doc, docErr := goquery.NewDocumentFromReader(responseHandler.Body(config.Opts.HTTPClientMaxBodySize()))
	if docErr != nil {
		return 0, docErr
	}

	timelengthMatches := timelengthRegex.FindStringSubmatch(doc.Text())
	if len(timelengthMatches) < 2 {
		return 0, errors.New("duration has not found")
	}

	durationMs, err := strconv.ParseInt(timelengthMatches[1], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("unable to parse duration %s: %v", timelengthMatches[1], err)
	}

	durationSec := durationMs / 1000
	durationMin := durationSec / 60
	if durationSec%60 != 0 {
		durationMin++
	}

	return int(durationMin), nil
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
			d += (time.Duration(val) * time.Hour)
		case "minute":
			d += (time.Duration(val) * time.Minute)
		case "second":
			d += (time.Duration(val) * time.Second)
		default:
			return 0, fmt.Errorf("unknown field %s", name)
		}
	}

	return d, nil
}

func isRecentEntry(entry *model.Entry) bool {
	if config.Opts.FilterEntryMaxAgeDays() == 0 || entry.Date.After(time.Now().AddDate(0, 0, -config.Opts.FilterEntryMaxAgeDays())) {
		return true
	}
	return false
}

func minifyEntryContent(entryContent string) string {
	m := minify.New()

	// Options required to avoid breaking the HTML content.
	m.Add("text/html", &html.Minifier{
		KeepEndTags: true,
		KeepQuotes:  true,
	})

	if minifiedHTML, err := m.String("text/html", entryContent); err == nil {
		entryContent = minifiedHTML
	}

	return entryContent
}
