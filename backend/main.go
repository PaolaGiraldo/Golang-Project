package main

import (
	"encoding/json"
	"fmt"
	"github.com/buaazp/fasthttprouter"
	"github.com/valyala/fasthttp"
	"github.com/likexian/whois-go"
	"log"
	"net/http"
	"strings"
	"regexp"
	"io/ioutil"
	"database/sql"
	_ "github.com/lib/pq"
)

type Output struct {
	Servers []Server
	Servers_changed bool
	Ssl_grade string
	Previous_ssl_grade string
	Logo string
	Title string
	Is_down bool


}


type Server struct {
	Address string
	Ssl_grade string
	Country string
	Owner string;
}
const (
	host     = "localhost"
	port     = 26257
	user     = "maxroach"
	dbname   = "serversinfo"
)

var info = &Output{
	 servers,
	false,
	"",
	"",
	"",
	"",
	false,
}
var servers []Server


var info_whois = "#" +
"\n# ARIN WHOIS data and services are subject to the Terms of Use" +
"\n# available at: https://www.arin.net/resources/registry/whois/tou/" +
"\n#" +
"\n# If you see inaccuracies in the results, please report at" +
"\n# https://www.arin.net/resources/registry/whois/inaccuracy_reporting/" +
"\n#" +
"\n# Copyright 1997-2020, American Registry for Internet Numbers, Ltd." +
"\n#" +
"\n" +
"\n"

var re_endpoints = regexp.MustCompile(`\[([^\[\]]*)\]`)
var re_country = regexp.MustCompile(`\bCountry\b:\s{8}[a-zA-Z]*`) // para encontrar la linea que tiene el pais
var re_owner = regexp.MustCompile(`\bOrgName\b:\s{8}[a-zA-Z0-9].*`) // para encontrar la linea que tiene la compañia
var re_ipv4 = regexp.MustCompile(`(?:[0-9]{1,3}\.){3}[0-9]{1,3}`) // para encontrar la linea que tiene las ips
var re_ipv6 = regexp.MustCompile(`((?:[0-9A-Fa-f]{1,4}))((?::[0-9A-Fa-f]{1,4}))*::((?:[0-9A-Fa-f]{1,4}))((?::[0-9A-Fa-f]{1,4}))*|((?:[0-9A-Fa-f]{1,4}))((?::[0-9A-Fa-f]{1,4})){7}`)
var re_grade = regexp.MustCompile(`\"\bgrade\b\":\"[A-Z]\"`)

var ips []string


func getSsl(ctx *fasthttp.RequestCtx){

	info = nil
	servers = nil

	//Configure request
	ctx.Response.Header.Set("Access-Control-Allow-Origin","*")
	ctx.Request.Header.Set("Access-Control-Allow-Origin","*")
	ctx.Request.Header.Set("Content-Type", "application/json; charset=UTF-8")
	ctx.Request.Header.Set("AllowedHeaders", "Content-Type,Bearer,Bearer,content-type,Origin,Accept")
	ctx.Request.Header.Set("OptionsPassthrough", "true")

	// Guardar el dominio en la base de datos
	domain := ctx.UserValue("domain")

	psqlInfo := fmt.Sprintf("host=%s port=%d user=%s dbname=%s sslmode=disable",
		host, port, user, dbname)
	// Connect to the "bank" database.
	db, err := sql.Open("postgres", psqlInfo)
	if err != nil {
		log.Fatal("error connecting to the database: ", err)
	}
	defer db.Close()

	string_db := domain.(string) + " info"
	if _, err := db.Exec(
		"INSERT INTO serversinfo (ServerName)\n VALUES ($1) ON CONFLICT (ServerName) DO NOTHING", string_db); err != nil {
		log.Fatal(err)
	}

	// Consulta Whois
	clienteHttp := &http.Client{}

	url := "https://api.ssllabs.com/api/v3/analyze?host=" + domain.(string)

	peticion, err := http.NewRequest("GET", url, nil)
	respuesta, err := clienteHttp.Do(peticion)

	defer respuesta.Body.Close()

	cuerpoRespuesta, err := ioutil.ReadAll(respuesta.Body)
	if err != nil {
		log.Fatalf("Error leyendo respuesta: %v", err)
	}

	// Organizar Json
	ssl_response := string(cuerpoRespuesta[:])
	endpoints := re_endpoints.FindAllString(ssl_response, -1)
	endpoints = strings.SplitAfter(string(cuerpoRespuesta[:]),"},")


	for _, item := range endpoints{
		ip := re_ipv4.FindAllString(item, -1)

	if ip==nil {
		ip = re_ipv6.FindAllString(item, -1)
	}

	ip_string := strings.Join(ip," ")
	result, err := whois.Whois(ip_string)

	if err != nil {
		json.NewEncoder(ctx).Encode(err)
	}

	match_country := re_country.FindAllString(result, -1)
	match_owner := re_owner.FindAllString(result, -1)
	match_grade := re_grade.FindAllString(item, -1)

	//to String
	String_country := strings.Join(match_country ," ")
	String_owner := strings.Join(match_owner ," ")
	String_grade := strings.Join(match_grade ," ")


	owner := strings.Trim(String_owner,"OrgName:        ")
	country := strings.Trim(String_country,"Country:        ")
	grade := strings.Trim(String_grade,"\"grade\":")

	servers = append(servers,Server{Address:ip_string, Country:country, Ssl_grade: grade, Owner: owner})


	}

	info = &Output{Servers:servers,Servers_changed: false,Ssl_grade: "A",Previous_ssl_grade: "A",Logo: "logo.png",Title: "Title",Is_down: false}
	json.NewEncoder(ctx).Encode(info)
}


func database(ctx *fasthttp.RequestCtx) {

	ctx.Response.Header.Set("Access-Control-Allow-Origin","*")
	ctx.Request.Header.Set("Access-Control-Allow-Origin","*")

	var servers []string
	psqlInfo := fmt.Sprintf("host=%s port=%d user=%s dbname=%s sslmode=disable",
		host, port, user, dbname)
	// Connect to the database.
	db, err := sql.Open("postgres", psqlInfo)
	if err != nil {
		log.Fatal("error connecting to the database: ", err)
	}

	rows, err := db.Query("SELECT * from serversinfo")
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	for rows.Next() {
		var servername string
		if err := rows.Scan(&servername); err != nil {
			log.Fatal(err)
		}

		servers = append(servers,servername)
	}

	json.NewEncoder(ctx).Encode(servers)

}

func main(){

	router := fasthttprouter.New()

	//endpoints
	router.POST("/ssl/host=:domain", getSsl)
	router.GET("/db", database)

	//servidor escuchando
	log.Fatal(fasthttp.ListenAndServe(":8082", router.Handler))


}




