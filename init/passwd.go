package main

import (
	"bufio"
	"os"
	"strings"
)

type User struct {
	// 'man 5 passwd' name:password:UID:GID:GECOS:directory:shell
	Name     string
	Password string
	Uid      string
	Gid      string
	Gecos    string
	Home     string
	Shell    string
}

/*
func GetHome(passwd string, name string) string {
	u := GetUser(passwd, name)
	if u != nil {
		return u.Home
	}
	if name == "root" {
		return "/root"
	}
	return  "/home/" + name
}
*/

func GetUser(passwd string, name string) *User {
	passwdFile, err := os.Open(passwd)
	if err != nil {
		return nil
	}
	defer passwdFile.Close()

	sc := bufio.NewScanner(passwdFile)
	u := User{}
	for sc.Scan() {
		l := strings.SplitN(sc.Text(), ":", 7)
		if len(l) != 7 {
			println("invalid passwd line: ", sc.Text())
			continue
		}
		u = User{Name: l[0], Password: l[1], Uid: l[2], Gid: l[3], Gecos: l[4], Home: l[5], Shell: l[6]}
		if u.Name == name {
			return &u
		}
	}
	return nil
}
