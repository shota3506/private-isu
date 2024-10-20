package main

import (
	"bytes"
	crand "crypto/rand"
	"crypto/sha512"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/bradfitz/gomemcache/memcache"
	gsm "github.com/bradleypeabody/gorilla-sessions-memcache"
	"github.com/go-chi/chi/v5"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/sessions"
	"github.com/jmoiron/sqlx"
)

//go:embed templates/*
var files embed.FS

var (
	db             *sqlx.DB
	memcacheClient *memcache.Client
	store          *gsm.MemcacheStore

	accountNameRegexp = regexp.MustCompile(`\A[0-9a-zA-Z_]{3,}\z`)
	passwordRegexp    = regexp.MustCompile(`\A[0-9a-zA-Z_]{6,}\z`)
)

const (
	iso8601Format = "2006-01-02T15:04:05-07:00"
	uploadLimit   = 10 * 1024 * 1024 // 10mb
)

type User struct {
	ID          int       `db:"id"`
	AccountName string    `db:"account_name"`
	Passhash    string    `db:"passhash"`
	Authority   int       `db:"authority"`
	DelFlg      int       `db:"del_flg"`
	CreatedAt   time.Time `db:"created_at"`
}

type Post struct {
	ID           int       `db:"id"`
	UserID       int       `db:"user_id"`
	Imgdata      []byte    `db:"imgdata"`
	Body         string    `db:"body"`
	Mime         string    `db:"mime"`
	CreatedAt    time.Time `db:"created_at"`
	User         User      `db:"user"`
	CommentCount int
	Comments     []Comment
	CSRFToken    string
}

type Comment struct {
	ID        int       `db:"id"`
	PostID    int       `db:"post_id"`
	UserID    int       `db:"user_id"`
	Comment   string    `db:"comment"`
	CreatedAt time.Time `db:"created_at"`
	User      User      `db:"user"`
}

func init() {
	memdAddr := os.Getenv("ISUCONP_MEMCACHED_ADDRESS")
	if memdAddr == "" {
		memdAddr = "localhost:11211"
	}
	memcacheClient = memcache.New(memdAddr)
	store = gsm.NewMemcacheStore(memcacheClient, "iscogram_", []byte("sendagaya"))
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
}

func commentsCountCacheKey(id int) string {
	return fmt.Sprintf("comments.%d.count", id)
}

func commentsCacheKey(id int, all bool) string {
	return fmt.Sprintf("comments.%d.%t", id, all)
}

func dbInitialize() {
	sqls := []string{
		"DELETE FROM users WHERE id > 1000",
		"DELETE FROM posts WHERE id > 10000",
		"DELETE FROM comments WHERE id > 100000",
		"UPDATE users SET del_flg = 0",
		"UPDATE users SET del_flg = 1 WHERE id % 50 = 0",
	}

	for _, sql := range sqls {
		db.Exec(sql)
	}
}

func tryLogin(accountName, password string) *User {
	u := User{}
	err := db.Get(&u, "SELECT * FROM users WHERE account_name = ? AND del_flg = 0", accountName)
	if err != nil {
		return nil
	}

	if calculatePasshash(u.AccountName, password) == u.Passhash {
		return &u
	} else {
		return nil
	}
}

func validateUser(accountName, password string) bool {
	return accountNameRegexp.MatchString(accountName) &&
		passwordRegexp.MatchString(password)
}

func digest(src string) string {
	return fmt.Sprintf("%x", sha512.Sum512([]byte(src)))
}

func calculateSalt(accountName string) string {
	return digest(accountName)
}

func calculatePasshash(accountName, password string) string {
	return digest(password + ":" + calculateSalt(accountName))
}

func getSession(r *http.Request) *sessions.Session {
	session, _ := store.Get(r, "isuconp-go.session")
	return session
}

func getSessionUser(r *http.Request) User {
	session := getSession(r)
	uid, ok := session.Values["user_id"]
	if !ok || uid == nil {
		return User{}
	}

	u := User{}

	err := db.Get(&u, "SELECT * FROM `users` WHERE `id` = ?", uid)
	if err != nil {
		return User{}
	}

	return u
}

func getFlash(w http.ResponseWriter, r *http.Request, key string) string {
	session := getSession(r)
	value, ok := session.Values[key]

	if !ok || value == nil {
		return ""
	} else {
		delete(session.Values, key)
		session.Save(r, w)
		return value.(string)
	}
}

func makePosts(results []Post, csrfToken string, allComments bool) ([]Post, error) {
	countCacheKeys := make([]string, 0, len(results))
	commentsCacheKeys := make([]string, 0, len(results))
	for _, result := range results {
		countCacheKeys = append(countCacheKeys, commentsCountCacheKey(result.ID))
		commentsCacheKeys = append(commentsCacheKeys, commentsCacheKey(result.ID, allComments))
	}

	cachedCounts, err := memcacheClient.GetMulti(countCacheKeys)
	if err != nil {
		return nil, err
	}
	cachedComments, err := memcacheClient.GetMulti(commentsCacheKeys)
	if err != nil {
		return nil, err
	}

	posts := make([]Post, 0, len(results))
	for _, result := range results {
		// comments count
		cachedCount, ok := cachedCounts[commentsCountCacheKey(result.ID)]
		if ok {
			count, _ := strconv.Atoi(string(cachedCount.Value))
			result.CommentCount = count
		} else {
			err = db.Get(&result.CommentCount, "SELECT COUNT(*) AS `count` FROM `comments` WHERE `post_id` = ?", result.ID)
			if err != nil {
				return nil, err
			}

			if err := memcacheClient.Set(&memcache.Item{
				Key:        commentsCountCacheKey(result.ID),
				Value:      []byte(strconv.Itoa(result.CommentCount)),
				Expiration: 10,
			}); err != nil {
				return nil, err
			}
		}

		// comments
		cachedComments, ok := cachedComments[commentsCacheKey(result.ID, allComments)]
		if ok {
			var comments []Comment
			if err := json.Unmarshal(cachedComments.Value, &comments); err != nil {
				return nil, err
			}
			result.Comments = comments
		} else {
			query := "SELECT `comments`.`id` AS `id`, `comments`.`post_id` AS `post_id`, `comments`.`user_id` AS `user_id`, `comments`.`comment` AS `comment`, `comments`.`created_at` AS `created_at`, `users`.`account_name` AS `user.account_name` " +
				"FROM `comments` " +
				"JOIN `users` ON `comments`.`user_id` = `users`.`id` " +
				"WHERE `comments`.`post_id` = ? ORDER BY `comments`.`created_at` DESC"
			if !allComments {
				query += " LIMIT 3"
			}
			var comments []Comment
			err = db.Select(&comments, query, result.ID)
			if err != nil {
				return nil, err
			}
			// reverse
			for i, j := 0, len(comments)-1; i < j; i, j = i+1, j-1 {
				comments[i], comments[j] = comments[j], comments[i]
			}
			result.Comments = comments

			v, err := json.Marshal(comments)
			if err != nil {
				return nil, err
			}
			if err := memcacheClient.Set(&memcache.Item{
				Key:        commentsCacheKey(result.ID, allComments),
				Value:      v,
				Expiration: 10,
			}); err != nil {
				return nil, err
			}
		}

		result.CSRFToken = csrfToken

		posts = append(posts, result)
	}

	return posts, nil
}

func imageURL(p Post) string {
	ext := ""
	if p.Mime == "image/jpeg" {
		ext = ".jpg"
	} else if p.Mime == "image/png" {
		ext = ".png"
	} else if p.Mime == "image/gif" {
		ext = ".gif"
	}

	return "/image/" + strconv.Itoa(p.ID) + ext
}

func isLogin(u User) bool {
	return u.ID != 0
}

func getCSRFToken(r *http.Request) string {
	session := getSession(r)
	csrfToken, ok := session.Values["csrf_token"]
	if !ok {
		return ""
	}
	return csrfToken.(string)
}

func secureRandomStr(b int) string {
	k := make([]byte, b)
	if _, err := crand.Read(k); err != nil {
		panic(err)
	}
	return fmt.Sprintf("%x", k)
}

func getTemplPath(filename string) string {
	return path.Join("templates", filename)
}

func getInitialize(w http.ResponseWriter, r *http.Request) {
	dbInitialize()
	w.WriteHeader(http.StatusOK)
}

var loginTemplate = template.Must(template.ParseFS(files,
	getTemplPath("layout.html"),
	getTemplPath("login.html")),
)

func getLogin(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)

	if isLogin(me) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	loginTemplate.Execute(w, struct {
		Me    User
		Flash string
	}{me, getFlash(w, r, "notice")})
}

func postLogin(w http.ResponseWriter, r *http.Request) {
	if isLogin(getSessionUser(r)) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	u := tryLogin(r.FormValue("account_name"), r.FormValue("password"))

	if u != nil {
		session := getSession(r)
		session.Values["user_id"] = u.ID
		session.Values["csrf_token"] = secureRandomStr(16)
		session.Save(r, w)

		http.Redirect(w, r, "/", http.StatusFound)
	} else {
		session := getSession(r)
		session.Values["notice"] = "アカウント名かパスワードが間違っています"
		session.Save(r, w)

		http.Redirect(w, r, "/login", http.StatusFound)
	}
}

var registerTemplate = template.Must(template.ParseFS(files,
	getTemplPath("layout.html"),
	getTemplPath("register.html")),
)

func getRegister(w http.ResponseWriter, r *http.Request) {
	if isLogin(getSessionUser(r)) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	registerTemplate.Execute(w, struct {
		Me    User
		Flash string
	}{User{}, getFlash(w, r, "notice")})
}

func postRegister(w http.ResponseWriter, r *http.Request) {
	if isLogin(getSessionUser(r)) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	accountName, password := r.FormValue("account_name"), r.FormValue("password")

	validated := validateUser(accountName, password)
	if !validated {
		session := getSession(r)
		session.Values["notice"] = "アカウント名は3文字以上、パスワードは6文字以上である必要があります"
		session.Save(r, w)

		http.Redirect(w, r, "/register", http.StatusFound)
		return
	}

	exists := 0
	// ユーザーが存在しない場合はエラーになるのでエラーチェックはしない
	db.Get(&exists, "SELECT 1 FROM users WHERE `account_name` = ?", accountName)

	if exists == 1 {
		session := getSession(r)
		session.Values["notice"] = "アカウント名がすでに使われています"
		session.Save(r, w)

		http.Redirect(w, r, "/register", http.StatusFound)
		return
	}

	query := "INSERT INTO `users` (`account_name`, `passhash`) VALUES (?,?)"
	result, err := db.Exec(query, accountName, calculatePasshash(accountName, password))
	if err != nil {
		log.Print(err)
		return
	}

	session := getSession(r)
	uid, err := result.LastInsertId()
	if err != nil {
		log.Print(err)
		return
	}
	session.Values["user_id"] = uid
	session.Values["csrf_token"] = secureRandomStr(16)
	session.Save(r, w)

	http.Redirect(w, r, "/", http.StatusFound)
}

func getLogout(w http.ResponseWriter, r *http.Request) {
	session := getSession(r)
	delete(session.Values, "user_id")
	session.Options = &sessions.Options{MaxAge: -1}
	session.Save(r, w)

	http.Redirect(w, r, "/", http.StatusFound)
}

var getIndexTemplate = template.Must(template.New("layout.html").Funcs(template.FuncMap{
	"imageURL": imageURL,
}).ParseFS(files,
	getTemplPath("layout.html"),
	getTemplPath("index.html"),
	getTemplPath("posts.html"),
	getTemplPath("post.html"),
))

func getIndex(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)

	results := []Post{}

	err := db.Select(&results, "SELECT `posts`.`id` AS `id`, `user_id`, `body`, `mime`, `posts`.`created_at` AS `created_at`, `users`.`account_name` AS `user.account_name` "+
		"FROM `posts` "+
		"JOIN `users` ON `posts`.`user_id` = `users`.`id` "+
		"WHERE `users`.`del_flg` = 0 "+
		"ORDER BY `posts`.`created_at` DESC LIMIT 20",
	)
	if err != nil {
		log.Print(err)
		return
	}

	posts, err := makePosts(results, getCSRFToken(r), false)
	if err != nil {
		log.Print(err)
		return
	}

	getIndexTemplate.Execute(w, struct {
		Posts     []Post
		Me        User
		CSRFToken string
		Flash     string
	}{posts, me, getCSRFToken(r), getFlash(w, r, "notice")})
}

var getAccountNameTemplate = template.Must(template.New("layout.html").Funcs(template.FuncMap{
	"imageURL": imageURL,
}).ParseFS(files,
	getTemplPath("layout.html"),
	getTemplPath("user.html"),
	getTemplPath("posts.html"),
	getTemplPath("post.html"),
))

func getAccountName(w http.ResponseWriter, r *http.Request) {
	accountName := r.PathValue("accountName")
	user := User{}

	err := db.Get(&user, "SELECT * FROM `users` WHERE `account_name` = ? AND `del_flg` = 0", accountName)
	if err != nil {
		log.Print(err)
		return
	}

	if user.ID == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	results := []Post{}

	err = db.Select(&results, "SELECT `posts`.`id` AS `id`, `user_id`, `body`, `mime`, `posts`.`created_at` AS `created_at`, `users`.`account_name` AS `user.account_name` "+
		"FROM `posts` FORCE INDEX(`idx_posts_user_id_created_at`) "+
		"JOIN `users` ON `posts`.`user_id` = `users`.`id` "+
		"WHERE `user_id` = ? AND `users`.`del_flg` = 0 "+
		"ORDER BY `posts`.`created_at` DESC LIMIT 20",
		user.ID,
	)
	if err != nil {
		log.Print(err)
		return
	}

	posts, err := makePosts(results, getCSRFToken(r), false)
	if err != nil {
		log.Print(err)
		return
	}

	commentCount := 0
	err = db.Get(&commentCount, "SELECT COUNT(*) AS count FROM `comments` WHERE `user_id` = ?", user.ID)
	if err != nil {
		log.Print(err)
		return
	}

	postIDs := []int{}
	err = db.Select(&postIDs, "SELECT `id` FROM `posts` WHERE `user_id` = ?", user.ID)
	if err != nil {
		log.Print(err)
		return
	}
	postCount := len(postIDs)

	commentedCount := 0
	if postCount > 0 {
		s := []string{}
		for range postIDs {
			s = append(s, "?")
		}
		placeholder := strings.Join(s, ", ")

		// convert []int -> []interface{}
		args := make([]interface{}, len(postIDs))
		for i, v := range postIDs {
			args[i] = v
		}

		err = db.Get(&commentedCount, "SELECT COUNT(*) AS count FROM `comments` WHERE `post_id` IN ("+placeholder+")", args...)
		if err != nil {
			log.Print(err)
			return
		}
	}

	me := getSessionUser(r)

	getAccountNameTemplate.Execute(w, struct {
		Posts          []Post
		User           User
		PostCount      int
		CommentCount   int
		CommentedCount int
		Me             User
	}{posts, user, postCount, commentCount, commentedCount, me})
}

var getPostsTemplate = template.Must(template.New("posts.html").Funcs(template.FuncMap{
	"imageURL": imageURL,
}).ParseFS(files,
	getTemplPath("posts.html"),
	getTemplPath("post.html"),
))

func getPosts(w http.ResponseWriter, r *http.Request) {
	m, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Print(err)
		return
	}
	maxCreatedAt := m.Get("max_created_at")
	if maxCreatedAt == "" {
		return
	}

	t, err := time.Parse(iso8601Format, maxCreatedAt)
	if err != nil {
		log.Print(err)
		return
	}

	results := []Post{}
	err = db.Select(&results, "SELECT `posts`.`id` AS `id`, `user_id`, `body`, `mime`, `posts`.`created_at` AS `created_at`, `users`.`account_name` AS `user.account_name` "+
		"FROM `posts` "+
		"JOIN `users` ON `posts`.`user_id` = `users`.`id` "+
		"WHERE `posts`.`created_at` <= ? AND `users`.`del_flg` = 0 "+
		"ORDER BY `posts`.`created_at` DESC LIMIT 20",
		t.Format(iso8601Format),
	)
	if err != nil {
		log.Print(err)
		return
	}

	posts, err := makePosts(results, getCSRFToken(r), false)
	if err != nil {
		log.Print(err)
		return
	}

	if len(posts) == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	getPostsTemplate.Execute(w, posts)
}

var getPostsIDTemplate = template.Must(template.New("layout.html").Funcs(template.FuncMap{
	"imageURL": imageURL,
}).ParseFS(files,
	getTemplPath("layout.html"),
	getTemplPath("post_id.html"),
	getTemplPath("post.html"),
))

func getPostsID(w http.ResponseWriter, r *http.Request) {
	pidStr := r.PathValue("id")
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	results := []Post{}
	err = db.Select(&results, "SELECT `posts`.`id` AS `id`, `user_id`, `body`, `mime`, `posts`.`created_at` AS `created_at`, `users`.`account_name` AS `user.account_name` "+
		"FROM `posts` "+
		"JOIN `users` ON `posts`.`user_id` = `users`.`id` "+
		"WHERE `posts`.`id` = ? AND `users`.`del_flg` = 0 "+
		"LIMIT 1",
		pid,
	)
	if err != nil {
		log.Print(err)
		return
	}

	posts, err := makePosts(results, getCSRFToken(r), true)
	if err != nil {
		log.Print(err)
		return
	}

	if len(posts) == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	p := posts[0]

	me := getSessionUser(r)

	getPostsIDTemplate.Execute(w, struct {
		Post Post
		Me   User
	}{p, me})
}

func postIndex(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)
	if !isLogin(me) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	if r.FormValue("csrf_token") != getCSRFToken(r) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		session := getSession(r)
		session.Values["notice"] = "画像が必須です"
		session.Save(r, w)

		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	mime, ext := "", ""
	if file != nil {
		// 投稿のContent-Typeからファイルのタイプを決定する
		contentType := header.Header["Content-Type"][0]
		if strings.Contains(contentType, "jpeg") {
			mime, ext = "image/jpeg", "jpg"
		} else if strings.Contains(contentType, "png") {
			mime, ext = "image/png", "png"
		} else if strings.Contains(contentType, "gif") {
			mime, ext = "image/gif", "gif"
		} else {
			session := getSession(r)
			session.Values["notice"] = "投稿できる画像形式はjpgとpngとgifだけです"
			session.Save(r, w)

			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
	}

	filedata, err := io.ReadAll(file)
	if err != nil {
		log.Print(err)
		return
	}

	if len(filedata) > uploadLimit {
		session := getSession(r)
		session.Values["notice"] = "ファイルサイズが大きすぎます"
		session.Save(r, w)

		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	query := "INSERT INTO `posts` (`user_id`, `mime`, `imgdata`, `body`) VALUES (?,?,?,?)"
	result, err := db.Exec(
		query,
		me.ID,
		mime,
		filedata,
		r.FormValue("body"),
	)
	if err != nil {
		log.Print(err)
		return
	}

	pid, err := result.LastInsertId()
	if err != nil {
		log.Print(err)
		return
	}

	if err := saveImage(pid, ext, filedata); err != nil {
		log.Print(err)
		return
	}

	http.Redirect(w, r, "/posts/"+strconv.FormatInt(pid, 10), http.StatusFound)
}

func getImage(w http.ResponseWriter, r *http.Request) {
	pidStr := r.PathValue("id")
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	post := Post{}
	err = db.Get(&post, "SELECT * FROM `posts` WHERE `id` = ?", pid)
	if err != nil {
		log.Print(err)
		return
	}

	ext := r.PathValue("ext")

	if !(ext == "jpg" && post.Mime == "image/jpeg") &&
		!(ext == "png" && post.Mime == "image/png") &&
		!(ext == "gif" && post.Mime == "image/gif") {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	// save image
	if err := saveImage(int64(pid), ext, post.Imgdata); err != nil {
		log.Print(err)
		return
	}

	w.Header().Set("Content-Type", post.Mime)
	if _, err := w.Write(post.Imgdata); err != nil {
		log.Print(err)
		return
	}
}

func saveImage(pid int64, ext string, data []byte) error {
	file, err := os.Create(path.Join("../public/image", fmt.Sprintf("%d.%s", pid, ext)))
	if err != nil {
		return err
	}
	defer file.Close()

	io.Copy(file, bytes.NewReader(data))
	return nil
}

func postComment(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)
	if !isLogin(me) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	if r.FormValue("csrf_token") != getCSRFToken(r) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		return
	}

	postID, err := strconv.Atoi(r.FormValue("post_id"))
	if err != nil {
		log.Print("post_idは整数のみです")
		return
	}

	query := "INSERT INTO `comments` (`post_id`, `user_id`, `comment`) VALUES (?,?,?)"
	_, err = db.Exec(query, postID, me.ID, r.FormValue("comment"))
	if err != nil {
		log.Print(err)
		return
	}

	// purge cache
	if err := memcacheClient.Delete(commentsCountCacheKey(postID)); err != nil && !errors.Is(err, memcache.ErrCacheMiss) {
		log.Print(err)
		return
	}
	if err := memcacheClient.Delete(commentsCacheKey(postID, true)); err != nil && !errors.Is(err, memcache.ErrCacheMiss) {
		log.Print(err)
		return
	}
	if err := memcacheClient.Delete(commentsCacheKey(postID, false)); err != nil && !errors.Is(err, memcache.ErrCacheMiss) {
		log.Print(err)
		return
	}

	http.Redirect(w, r, fmt.Sprintf("/posts/%d", postID), http.StatusFound)
}

var getAdminBannedTemplate = template.Must(template.ParseFS(files,
	getTemplPath("layout.html"),
	getTemplPath("banned.html")),
)

func getAdminBanned(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)
	if !isLogin(me) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	if me.Authority == 0 {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	users := []User{}
	err := db.Select(&users, "SELECT * FROM `users` WHERE `authority` = 0 AND `del_flg` = 0 ORDER BY `created_at` DESC")
	if err != nil {
		log.Print(err)
		return
	}

	getAdminBannedTemplate.Execute(w, struct {
		Users     []User
		Me        User
		CSRFToken string
	}{users, me, getCSRFToken(r)})
}

func postAdminBanned(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)
	if !isLogin(me) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	if me.Authority == 0 {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	if r.FormValue("csrf_token") != getCSRFToken(r) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		return
	}

	query := "UPDATE `users` SET `del_flg` = ? WHERE `id` = ?"

	err := r.ParseForm()
	if err != nil {
		log.Print(err)
		return
	}

	for _, id := range r.Form["uid[]"] {
		db.Exec(query, 1, id)
	}

	http.Redirect(w, r, "/admin/banned", http.StatusFound)
}

func main() {
	host := os.Getenv("ISUCONP_DB_HOST")
	if host == "" {
		host = "localhost"
	}
	port := os.Getenv("ISUCONP_DB_PORT")
	if port == "" {
		port = "3306"
	}
	_, err := strconv.Atoi(port)
	if err != nil {
		log.Fatalf("Failed to read DB port number from an environment variable ISUCONP_DB_PORT.\nError: %s", err.Error())
	}
	user := os.Getenv("ISUCONP_DB_USER")
	if user == "" {
		user = "root"
	}
	password := os.Getenv("ISUCONP_DB_PASSWORD")
	dbname := os.Getenv("ISUCONP_DB_NAME")
	if dbname == "" {
		dbname = "isuconp"
	}

	dsn := fmt.Sprintf(
		"%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=true&loc=Local&interpolateParams=true",
		user,
		password,
		host,
		port,
		dbname,
	)

	db, err = sqlx.Open("mysql", dsn)
	if err != nil {
		log.Fatalf("Failed to connect to DB: %s.", err.Error())
	}
	defer db.Close()

	db.SetMaxOpenConns(20)
	db.SetMaxIdleConns(20)

	r := chi.NewRouter()

	r.Get("/initialize", getInitialize)
	r.Get("/login", getLogin)
	r.Post("/login", postLogin)
	r.Get("/register", getRegister)
	r.Post("/register", postRegister)
	r.Get("/logout", getLogout)
	r.Get("/", getIndex)
	r.Get("/posts", getPosts)
	r.Get("/posts/{id}", getPostsID)
	r.Post("/", postIndex)
	r.Get("/image/{id}.{ext}", getImage)
	r.Post("/comment", postComment)
	r.Get("/admin/banned", getAdminBanned)
	r.Post("/admin/banned", postAdminBanned)
	r.Get(`/@{accountName:[a-zA-Z]+}`, getAccountName)
	r.Get("/*", func(w http.ResponseWriter, r *http.Request) {
		http.FileServer(http.Dir("../public")).ServeHTTP(w, r)
	})

	log.Fatal(http.ListenAndServe(":8080", r))
}
