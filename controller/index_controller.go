package controller

import (
	"bytes"
	"net/http"
	"text/template"

	"github.com/gin-gonic/gin"
)

// Index function
func Index(c *gin.Context) {
	if tmpl, err := template.ParseFiles("templates/welcome.html"); err != nil {
		panic(err)
	} else {
		buf := &bytes.Buffer{}
		if err = tmpl.Execute(buf, gin.H{"var": 4}); err != nil {
			panic(err)
		} else {
			c.Data(http.StatusOK, "text/html; charset=utf-8", buf.Bytes())
		}
	}
	buf := &bytes.Buffer{}
	c.Data(http.StatusOK, "text/html; charset=utf-8", buf.Bytes())
}
