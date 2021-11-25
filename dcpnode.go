package main

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"io/ioutil"
	"log"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/disk"
	"github.com/shirou/gopsutil/mem"
	"github.com/shirou/gopsutil/net"
	"github.com/tidwall/gjson"
)

var TIME_LOCATION_CST *time.Location

//1、磁盘  内存  cpu 网络 进程数量 信息获取   类型    disk  mem  cpu  network   pro
//2、进程管理  启动进程   关闭进程    参数
//3、传送文件    ip  username  passwd    port  source   dest
//4、日志查看   如果超过1M，截取100行
//5、定时任务   删除  创建

type Message struct {
	Taskid  string `json:"taskid"`
	Pid     string `json:"pid"`
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
		time.Sleep(time.Second * 10)
		var avgcpu float64

		cc, err := cpu.Percent(time.Second, false)
		if err != nil {
			log.Println("获取cpu状态错误", err.Error())
			return
		}
		for i := 0; i < len(cc); i++ {
			avgcpu = avgcpu + cc[i]
		}
		xx.cpu = avgcpu / float64(len(cc))

		v, err1 := mem.VirtualMemory()
		if err1 != nil {
			log.Println("获取内存状态错误", err.Error())
			return
		}
		xx.mem = v.UsedPercent
		xx.pointerLock.Lock()
		xx.cpu = (avgcpu/float64(len(cc)) + xx.cpu) / 2
		xx.mem = (v.UsedPercent + xx.mem) / 2
		xx.pointerLock.Unlock()
	}

}
//获取主机的相关信息，cpu，mem，disk，net
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
//http主函数
func (p *MyMux) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	//显示help
   if r.URL.Path == "/help"{
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	result:=`
	<h3>###/echo   检查服务状态</h3>
	<h3>###/api/cmd   执行任务接口  参数cmdname cmdp1 cmdp2 cmdp3 cmdp4 conf f</h3>
	<h4>/api/cmd      cmdname：sh命令</h4>
	<h4>/api/cmd      cmdp1：时间参数  now|60|-60 cmdp2 cmdp3 cmdp4 conf f</h4>
	<h4>/api/cmd      cmdp2 cmdp3 cmdp4 自定义参数</h4>
	<h4>/api/cmd      conf：根据json生成配置文件 f：删除原有配置文件</h4>
	<h3>###/api/cmd   执行任务接口  参数cmdname cmdp1 cmdp2 cmdp3 cmdp4 conf f</h3>
	`
	fmt.Fprintf(w, result)
	return 
   }

	//检查服务状态状态
	if r.URL.Path == "/echo" {
		w.Header().Set("Content-Type", "text/json; charset=utf-8")
		fmt.Fprintf(w, "{\"status\":\"ok\"}")
		return
	}

	//下载文件路径
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
			w.Header().Set("content-type", "text/css")
			w.WriteHeader(200)
			fmt.Fprintf(w, "file not found")
		} else {
			bs, _ := ioutil.ReadAll(file)

			w.Write(bs)

		}
		return
	}

	wr := r.Header
//鉴权验证，如果header中没有token，拒绝服务
	if wr.Get("token") != p.token && p.token != "" {
		fmt.Fprintf(w, "你没有权限访问该服务")
		return
	}

	//执行命令接口
	if r.URL.Path == "/api/cmd" {
		index(w, r, p)
		return
	}
//检测服务是否正常
	if r.URL.Path == "/echo" {
		w.Header().Set("Content-Type", "text/json; charset=utf-8")
		fmt.Fprintf(w, "{\"status\":\"ok\"}")
		return
	}
	//文件上传页面
	if r.URL.Path == "/api/u/52871b0b087ec704631523f0a1776c4a97d7836b" {
		upfile(w, r, p)
		return
	}
   //文件上传接口
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

//文件上传页面
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
//文件上传接口
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

//初始化，配置输出日志相关参数设置
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
	log.SetFlags(log.Ldate | log.Ltime)
	return
}

//命令接口
func getcmd(p *MyMux, command string, p1 string, p2 string, p3 string, p4 string, cmdtype string, cmduser string, cmdname string, taskid string) string {
//如果执行的不是sh命令，拒绝执行
	if len(command) < 4 || command[len(command)-3:] != ".sh" {
		log.Println("run cmd:"+command, ",执行命令非法，请检查", "taskid:"+taskid)
		return `{"taskid":"-1","pid":-1,"filelog":"","status":false,"errinfo:"执行命令非法，请检查"}`

	}
//如果执行命令不存在，返回提示
	if _, err := os.Stat(command); err != nil {
		log.Println("run cmd:"+command, ",执行脚本不存在，请检查", "taskid:"+taskid)
		return `{"taskid":"-1","pid":-1,"filelog":"","status":false,"errinfo:"执行脚本不存在，请检查"}`

	}
//检测当前主机cpu和内存是否超过阈值，如果超过拒绝服务
	if p.cpulimit < p.cpu || p.memlimit < p.mem {
		errinfo1 := "主机资源超标:cpu=" + strconv.FormatFloat(p.cpu, 'f', -1, 32) + "   mem=" + strconv.FormatFloat(p.mem, 'f', -1, 32)
		log.Println(errinfo1, ",执行命令被拒绝,run cmd:"+command, ",taskid:"+taskid+" p1:"+p1+" p2:"+p2+" p3:"+p3+" p4:"+p4)
		return `{"taskid":"-1","pid":-1,"filelog":"","status":false,"errinfo":"` + errinfo1 + `"}`
	}
	log.Println("run cmd:" + command + " $1:" + taskid+ " $2:" + p1 + " $3:" + p2 + " $4:" + p3 + " $5:" + p4 )
	var cc *exec.Cmd
	if p4 != "" {
		cc = exec.Command("bash", command, taskid, p1, p2, p3, p4)
	}
	if p3 != "" && p4 == "" {
		cc = exec.Command("bash", command, taskid, p1, p2, p3)
	}
	if p2 != "" && p3 == "" {
		cc = exec.Command("bash", command, taskid, p1, p2)
	}
	if p1 != "" && p2 == "" {
		cc = exec.Command("bash", command, taskid, p1)
	}
	if p1 == "" {
		cc = exec.Command("bash", command, taskid)
	}
//返回消息定义
	var msg Message
	msg.Taskid = taskid
	msg.Status = true
	msg.Filelog = "log/" + taskid + ".log"
	msg.Errinfo = ""
//启动线程执行命令
	go startsh(cc)
	//time.Sleep(time.Second * 2)
	
	//检查进程号
	a := `ps ux | awk '/` + taskid + `/ && !/awk/ {print $2}'`
	result, err := exec.Command("/bin/sh", "-c", a).Output()
	if err != nil {

		log.Println("获取进程号错误", err.Error())

		msg.Pid = "-1"
	} else {
		msg.Pid = strings.ReplaceAll(string(result), "\n", "|")
		log.Println("run cmd:" + command + " taskid:" + taskid + " pid:" + msg.Pid + " p1:" + p1 + " p2:" + p2 + " p3:" + p3 + " p4:" + p4)
	}
	aaa, _ := json.Marshal(msg)
	return string(aaa)
}
//启动进程
func startsh(cc *exec.Cmd) {

	if err := cc.Start(); err != nil {

		log.Println("exec sh error:", err)
	}
	cc.Wait()
}


//执行命令详细接口
func index(w http.ResponseWriter, r *http.Request, p *MyMux) {
	wr := w.Header()

	var cmdp1, cmdp2, cmdp3, cmdp4, cmduser, cmdtype string
	wr.Set("Content-Type", "text/html; charset=utf-8")
	defer r.Body.Close()
	r.ParseForm()





	//如果传参中配置了conf参数，就按照配置文件模板生成配置文件
	conf := r.Form["conf"]

	if len(conf) == 1 {

      //如果带f参数先删后更新
		f:=r.Form["f"]
		if len(f)==1{
			os.Remove(conf[0])
		}
		s, _ := ioutil.ReadAll(r.Body)
		reg := regexp.MustCompile(`{{[\w.]+}}`)

		str, err := ioutil.ReadFile(conf[0] + ".tmp")

		if err != nil {
			log.Println(err)
		}

		result := string(str)
		dataSlice := reg.FindAll(str, -1)
		for _, v := range dataSlice {
			//fmt.Println("vvvv:",string(v))
			aaaaaa := strings.ReplaceAll(string(v), "{", "")
			aaaaaa = strings.ReplaceAll(aaaaaa, "}", "")
			result = strings.ReplaceAll(result, string(v), gjson.Get(string(s), string(aaaaaa)).String())

		}

		//如果配置文件不存在，生成文件
		if _, err := os.Stat(conf[0]); err != nil {
			ioutil.WriteFile(conf[0], []byte(result), fs.FileMode(660))
		}

	}
	//获取任务号，必要参数
	taskid := r.Form["taskId"]
	if len(taskid) < 1 {
		return
	}
	//获取执行命令，必要参数
	cmdname := r.Form["cmdname"]
	if len(cmdname) < 1 {
		return
	}
	//btime := r.Form["btime"]
	//etime := r.Form["etime"]
//时间参数
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

//时间参数
	if len(r.Form["cmdp2"]) > 0 {
		cmdp2 = r.Form["cmdp2"][0]
	}
	if len(cmdp2) > 2 && strings.ToUpper(cmdp2[:3]) == "NOW" {

		allp1 := strings.Split(cmdp2, "|")
		if len(allp1) > 2 {
			inteval_int, _ := strconv.Atoi(allp1[1])
			number_int, _ := strconv.Atoi(allp1[2])

			t2 := time.Now().Add(time.Minute * time.Duration(number_int))
			cmdp2 = t2.Add(time.Minute * time.Duration(t2.Minute()%inteval_int*-1)).Format("2006-01-02T15:04:00")

		}

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
		fmt.Printf("build ver:\t%s\n", "20211028")

		os.Exit(0)
	}
	go func() {
		log.Println(http.ListenAndServe("localhost:9999", nil))
	}()

	var one sync.Mutex
	mux := &MyMux{token, 0, 0, one, cpulimit, memlimit}
	go setsystem(mux)
	log.Println("dcpnode starting,port:", port)
	err := http.ListenAndServe(":"+port, mux)
	if err != nil {
		log.Println("dcpnode start err:", err)
	}

}
