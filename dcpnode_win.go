package main

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/disk"
	"github.com/shirou/gopsutil/mem"
	"github.com/shirou/gopsutil/net"
)
var TIME_LOCATION_CST *time.Location
//1、磁盘  内存  cpu 网络 进程数量 信息获取   类型    disk  mem  cpu  network   pro
//2、进程管理  启动进程   关闭进程    参数
//3、传送文件    ip  username  passwd    port  source   dest
//4、日志查看   如果超过1M，截取100行
//5、定时任务   删除  创建

type Message struct {
	Taskid  string `json:"taskid"`
	Pid     int    `json:"pid"`
	Filelog string `json:"filelog"`
	Status  bool   `json:"status"`
	Errinfo string `json:"errinfo"`
}

type MyMux struct {
	token       string
	cpu         float64
	mem         float64
	pointerLock sync.Mutex
	cpulimit    float64
	memlimit    float64
}

func setsystem(xx *MyMux) {

	for {
		//	fmt.Println(xx.cpu)
		//	fmt.Println(xx.mem)
		time.Sleep(time.Second * 2)
		var avgcpu float64

		cc, _ := cpu.Percent(time.Second, false)
		for i := 0; i < len(cc); i++ {
			avgcpu = avgcpu + cc[i]
		}
		xx.cpu = avgcpu / float64(len(cc))

		v, _ := mem.VirtualMemory()
		xx.mem = v.UsedPercent
		xx.pointerLock.Lock()
		xx.cpu = (avgcpu/float64(len(cc)) + xx.cpu) / 2
		xx.mem = (v.UsedPercent + xx.mem) / 2
		xx.pointerLock.Unlock()
	}

}

func getmsg(w http.ResponseWriter, r *http.Request, typename string) {
	if typename == "cpu" {
		var avgcpu float64
		cc, _ := cpu.Percent(time.Second, false)
		for i := 0; i < len(cc); i++ {
			avgcpu = avgcpu + cc[i]
		}

		fmt.Fprintf(w, strconv.FormatFloat(avgcpu/float64(len(cc)), 'f', -1, 32))

	}
	if typename == "cpuinfo" {
		c, _ := cpu.Info()
		if len(c) > 1 {
			for _, sub_cpu := range c {
				modelname := sub_cpu.ModelName
				cores := sub_cpu.Cores
				fmt.Fprintf(w, "CPU:%v %v cores \n", modelname, cores)
			}
		} else {
			sub_cpu := c[0]
			modelname := sub_cpu.ModelName
			cores := sub_cpu.Cores
			fmt.Fprintf(w, "CPU:%v %v cores \n", modelname, cores)

		}

	}

	if typename == "disk" {
		d, _ := disk.Usage("/opt") //指定某路径的硬盘使用情况

		fmt.Fprintf(w, "/opt %v GB  Free: %v GB Usage:%f%%\n", d.Total/1024/1024/1024, d.Free/1024/1024/1024, d.UsedPercent)
		d, _ = disk.Usage("/home")
		fmt.Fprintf(w, "/home: %v GB  Free: %v GB Usage:%f%%\n", d.Total/1024/1024/1024, d.Free/1024/1024/1024, d.UsedPercent)

	}

	if typename == "mem" {
		v, _ := mem.VirtualMemory()
		v2, _ := mem.SwapMemory()

		fmt.Fprintf(w, "Mem: %v MB Free: %v MB Used:%v Usage:%f%%\n", v.Total/1024/1024, v.Available/1024/1024, v.Used/1024/1024, v.UsedPercent)

		fmt.Fprintf(w, "Swap: %v MB Used:%v Usage:%f%%\n", v2.Total/1024/1024, v2.Used/1024/1024, v2.UsedPercent)

	}

	if typename == "net" {
		nv, _ := net.IOCounters(false)
		time.Sleep(time.Second)
		nv1, _ := net.IOCounters(false)

		fmt.Fprintf(w, "Network: recv %v bytes / send %v bytes\n", (nv1[0].BytesRecv - nv[0].BytesRecv), (nv1[0].BytesSent - nv[0].BytesSent))

	}
}

func (p *MyMux) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/echo" {
		w.Header().Set("Content-Type", "text/json; charset=utf-8")
		fmt.Fprintf(w, "{\"status\":\"ok\"}")
		return
	}

	if len(r.URL.Path) > 2 && r.URL.Path[:2] == "/s" {

		filePath := r.URL.Path[len("/s"):]
		if filePath[len(filePath)-4:] == "xlsx" {
			w.Header().Set("content-type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
		} else if filePath[len(filePath)-4:] == "json" {
			w.Header().Set("Content-Type", "text/json; charset=utf-8")
		} else if filePath[len(filePath)-3:] == "log" {
			w.Header().Set("Content-Type", "text/json; charset=utf-8")
		} else if filePath[len(filePath)-3:] == "xml" {
			w.Header().Set("content-type", "text/xml; charset=utf-8")
		} else if filePath[len(filePath)-4:] == "html" {
			w.Header().Set("content-type", "text/html; charset=utf-8")
		} else if filePath[len(filePath)-3:] == "gif" {
			w.Header().Set("content-type", "image/gif")
		} else if filePath[len(filePath)-3:] == "jpg" {
			w.Header().Set("content-type", "image/jpeg")
		} else if filePath[len(filePath)-3:] == "png" {
			w.Header().Set("content-type", "image/png")
		} else if filePath[len(filePath)-3:] == "css" {
			w.Header().Set("content-type", "text/css")
		} else {
			w.Header().Set("content-type", "application/octet-stream")
		}
		file, err := os.Open("./" + filePath)
		defer file.Close()
		if err != nil {

			w.WriteHeader(404)
		} else {
			bs, _ := ioutil.ReadAll(file)

			w.Write(bs)

		}
		return
	}

	wr := r.Header

	if wr.Get("token") != p.token && p.token != "" {
		fmt.Fprintf(w, "你没有权限访问该服务")
		return
	}
	if r.URL.Path == "/api/cmd" {
		index(w, r, p)
		return
	}

	if r.URL.Path == "/echo" {
		w.Header().Set("Content-Type", "text/json; charset=utf-8")
		fmt.Fprintf(w, "{\"status\":\"ok\"}")
		return
	}
	if r.URL.Path == "/api/u/52871b0b087ec704631523f0a1776c4a97d7836b" {
		upfile(w, r, p)
		return
	}

	if r.URL.Path == "/upfilehand" {
		upfilehand(w, r, p)
		return
	}

	if r.URL.Path == "/cpu" {
		getmsg(w, r, "cpu")
		return
	}

	if r.URL.Path == "/cpuinfo" {
		getmsg(w, r, "cpuinfo")
		return
	}

	if r.URL.Path == "/disk" {
		getmsg(w, r, "disk")
		return
	}

	if r.URL.Path == "/mem" {
		getmsg(w, r, "mem")
		return
	}

	if r.URL.Path == "/net" {
		getmsg(w, r, "net")
		return
	}

}
func upfile(w http.ResponseWriter, r *http.Request, p *MyMux) {

	uploadHTML := `<!DOCTYPE html>

 <html> 
 <head> 
 
 <title>proxy</title>
 </head> 
 <body> 
 <form enctype="multipart/form-data" action="/upfilehand" method="post"> 
 <div class="imgBox">
 <input type="file" name="uploadfile" /><br> 
 <input type="submit" value="上传文件" /> <br>

 </div>
 </form> 
 </body> 
 </html>`

	wr := w.Header()
	wr.Set("Content-Type", "text/html; charset=utf-8")

	fmt.Fprintf(w, uploadHTML)

}
func upfilehand(w http.ResponseWriter, r *http.Request, p *MyMux) {
	if r.Method == "GET" {
		upfile(w, r, p)
		return
	}

	r.ParseMultipartForm(32 << 30) // max memory is set to 32MB

	clientfd, handler, err := r.FormFile("uploadfile")
	if err != nil {
		fmt.Println(err)
		w.Write([]byte("upload failed."))
		return
	}
	defer clientfd.Close()

	localpath := fmt.Sprintf("%s%s", "./files/", handler.Filename)
	localfd, err := os.OpenFile(localpath, os.O_WRONLY|os.O_CREATE, 0666)
	if err != nil {
		fmt.Println(err)
		w.Write([]byte("upload failed."))
		return
	}
	defer localfd.Close()

	// 利用io.TeeReader在读取文件内容时计算hash值
	fhash := sha1.New()
	io.Copy(localfd, io.TeeReader(clientfd, fhash))
	hstr := hex.EncodeToString(fhash.Sum(nil))
	w.Write([]byte(fmt.Sprintf("upload finish:%s", hstr)))
}
func init() {
	TIME_LOCATION_CST, _ = time.LoadLocation("Asia/Shanghai")
	
	_ = os.Mkdir("log", 755)
	file := "./log/dcpnode.log"

	logFile, err := os.OpenFile(file, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0766)
	if err != nil {
		panic(err)
	}
	log.SetOutput(logFile) // 将文件设置为log输出的文件
	log.SetPrefix("[dcpnode]")
	//日志标识
	log.SetFlags(log.Ldate | log.Ltime )
	return
}

func getcmd(p *MyMux, command string, p1 string, p2 string, p3 string, p4 string, cmdtype string, cmduser string, cmdname string, taskid string) string {
  
    

	if len(command) < 5 || command[len(command)-4:] != ".bat" {
		return `{"taskid":"-1","pid":-1,"filelog":"","status":false,"errinfo:"执行命令非法，请检查"}`
	}
	if _, err := os.Stat(command); err != nil {

		return `{"taskid":"-1","pid":-1,"filelog":"","status":false,"errinfo:"执行脚本不存在，请检查"}`

	}

	if p.cpulimit < p.cpu || p.memlimit < p.mem {
		errinfo1 := "主机资源超标:cpu=" + strconv.FormatFloat(p.cpu, 'f', -1, 32) + "   mem=" + strconv.FormatFloat(p.mem, 'f', -1, 32)

		return `{"taskid":"-1","pid":-1,"filelog":"","status":false,"errinfo":"` + errinfo1 + `"}`
	}
	log.Println("run cmd:" + command + " p1:" + p1 + " p2:" + p2 + " p3:" + p3 + " p4:" + p4 + " taskid:" + taskid)
	var cc *exec.Cmd
	if p4 != "" {
		cc = exec.Command("cmd","/C", command, taskid, p1, p2, p3, p4)
	}
	if p3 != "" && p4 == "" {
		cc = exec.Command("cmd","/C", command, taskid, p1, p2, p3)
	}
	if p2 != "" && p3 == "" {
		cc = exec.Command("cmd", "/C",command, taskid, p1, p2)
	}
	if p1 != "" && p2 == "" {
		cc = exec.Command("cmd","/C", command, taskid, p1)
	}
	if p1 == "" {
		cc = exec.Command("cmd","/C", command, taskid)
	}
	var msg Message
	msg.Pid = 11111
	msg.Taskid = taskid
	msg.Status = true
	msg.Filelog = "log/" + taskid + ".log"
	msg.Errinfo = ""
	aaa, _ := json.Marshal(msg)
	go startsh(cc)
	
	return string(aaa)
}

func startsh(cc *exec.Cmd){
	
	if err := cc.Start(); err != nil {
	
		log.Println("exec sh error:",err)	
	} else{
		cc.Wait()
	}
}

func index(w http.ResponseWriter, r *http.Request, p *MyMux) {
	wr := w.Header()

	var cmdp1, cmdp2, cmdp3, cmdp4, cmduser, cmdtype string
	wr.Set("Content-Type", "text/html; charset=utf-8")
	defer r.Body.Close()
	r.ParseForm()
	taskid := r.Form["taskId"]
	if len(taskid) < 1 {
		return
	}
	cmdname := r.Form["cmdname"]
	if len(cmdname) < 1 {
		return
	}
	//btime := r.Form["btime"]
	//etime := r.Form["etime"]

	if len(r.Form["cmdp1"]) > 0 {
		cmdp1 = r.Form["cmdp1"][0]
	}

	if len(cmdp1) > 2 && strings.ToUpper(cmdp1[:3]) == "NOW" {

		allp1 := strings.Split(cmdp1, "|")
		if len(allp1) > 2 {
			inteval_int, _ := strconv.Atoi(allp1[1])
			number_int, _ := strconv.Atoi(allp1[2])

			t2 := time.Now().Add(time.Minute * time.Duration(number_int))
			cmdp1 = t2.Add(time.Minute * time.Duration(t2.Minute()%inteval_int*-1)).Format("2006-01-02T15:04:00")

		}

	}
	if len(r.Form["cmdp2"]) > 0 {
		cmdp2 = r.Form["cmdp2"][0]
	}
	if len(r.Form["cmdp3"]) > 0 {
		cmdp3 = r.Form["cmdp3"][0]
	}
	if len(r.Form["cmdp4"]) > 0 {
		cmdp4 = r.Form["cmdp4"][0]
	}

	if len(r.Form["user"]) > 0 {
		cmduser = r.Form["user"][0]
	}
	if len(r.Form["type"]) > 0 {
		cmdtype = r.Form["type"][0]
	}
	switch cmdtype {
	case "xml":
		w.Header().Set("content-type", "text/xml; charset=utf-8")
	case "json":
		w.Header().Set("Content-Type", "text/json; charset=utf-8")
	default:
		w.Header().Set("content-type", "text/html; charset=utf-8")
	}

	fmt.Fprintf(w, getcmd(p, cmdname[0], cmdp1, cmdp2, cmdp3, cmdp4, cmdtype, cmduser, cmdname[0], taskid[0]))

}

func main() {

	var showVer bool
	var port string
	var token string
	var cpulimit, memlimit float64
	flag.StringVar(&port, "p", "4321", "dcpnode port")
	flag.StringVar(&token, "token", "dG9uZ3RlY2guY29t", "dcpnode token")
	flag.Float64Var(&cpulimit, "cpulimit", 99, "Denial of service after CPU value exceeds")
	flag.Float64Var(&memlimit, "memlimit", 98, "Denial of service after MEM value exceeds")
	flag.BoolVar(&showVer, "v", false, "show build version")

	flag.Parse()

	if showVer {
		// Printf( "build name:\t%s\nbuild ver:\t%s\nbuild time:\t%s\nCommitID:%s\n", BuildName, BuildVersion, BuildTime, CommitID )
		fmt.Printf("build name:\t%s\n", "dcpnode")
		fmt.Printf("build ver:\t%s\n", "20211011")

		os.Exit(0)
	}
	//layout := "2006-01-02 15:04:05"
	//log.Println("本程序为测试程序，测试截止日期为2019年11月15日")
	//time.Sleep(time.Duration(5) * time.Second)
	// just one second
	var one sync.Mutex
	mux := &MyMux{token, 0, 0, one, cpulimit, memlimit}
	go setsystem(mux)
	log.Println("dcpnode starting,port:", port)
	err := http.ListenAndServe(":"+port, mux)
	if err != nil {
		log.Println("dcpnode start err:", err)
	}

}
