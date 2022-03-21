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

type OmcCfg struct {
	Total int                      `json:"total"`
	Code  int                      `json:"code"`
	Rows  []map[string]interface{} `json:"rows"`
}

type Message struct {
	Taskid  string `json:"taskid"`
	Pid     string `json:"pid"`
	Filelog string `json:"filelog"`
	Status  int    `json:"status"`
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
	if r.URL.Path == "/help" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		result := `
	<h3>###/echo   检查服务状态</h3>
	<h3>###/api/cmd   执行任务接口  参数cmdname cmdp1 cmdp2 cmdp3 cmdp4 conf f</h3>
	<h4>/api/cmd      cmdname：sh命令</h4>
	<h4>/api/cmd      cmdp1：时间参数  now|60|-60 cmdp2 cmdp3 cmdp4 conf f</h4>
	<h4>/api/cmd      cmdp2 cmdp3 cmdp4 自定义参数</h4>

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
		log.Println(err)
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
		return `{"taskid":"-1","pid":-1,"filelog":"","status":2,"errinfo":"执行命令非法，请检查"}`

	}
	//如果执行命令不存在，返回提示
	if _, err := os.Stat(command); err != nil {
		log.Println("run cmd:"+command, ",执行脚本不存在，请检查", "taskid:"+taskid)
		return `{"taskid":"-1","pid":-1,"filelog":"","status":2,"errinfo":"执行脚本不存在，请检查"}`

	}
	//检测当前主机cpu和内存是否超过阈值，如果超过拒绝服务
	if p.cpulimit < p.cpu || p.memlimit < p.mem {
		errinfo1 := "主机资源超标:cpu=" + strconv.FormatFloat(p.cpu, 'f', -1, 32) + "   mem=" + strconv.FormatFloat(p.mem, 'f', -1, 32)
		log.Println(errinfo1, ",执行命令被拒绝,run cmd:"+command, ",taskid:"+taskid+" p1:"+p1+" p2:"+p2+" p3:"+p3+" p4:"+p4)
		return `{"taskid":"-1","pid":-1,"filelog":"","status":1,"errinfo":"` + errinfo1 + `"}`
	}
	log.Println("run cmd:" + command + " $1:" + taskid + " $2:" + p1 + " $3:" + p2 + " $4:" + p3 + " $5:" + p4)
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
	msg.Status = 0
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

//API请求
func httppost(token string, url string, body string) (string, error) {
	client := &http.Client{}
	b := strings.NewReader(body)
	req, err := http.NewRequest("POST", url, b)
	req.Header.Set("Content-Type", "text/json; charset=utf-8")
	req.Header.Set("token", token)
	res, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	body1, _ := ioutil.ReadAll(res.Body)
	return string(body1), nil
}

//执行命令详细接口
func index(w http.ResponseWriter, r *http.Request, p *MyMux) {
	wr := w.Header()
	var aaaaaa, bbbbbb, dataurl, token string
	var cmdp1, cmdp2, cmdp3, cmdp4, cmduser, cmdtype, cmdname, taskid, conf, hash, omcconf string
	wr.Set("Content-Type", "text/html; charset=utf-8")
	defer r.Body.Close()
	r.ParseForm()

	s, _ := ioutil.ReadAll(r.Body)

	if len(r.Form["taskId"]) > 0 {
		taskid = r.Form["taskId"][0]
	} else {
		taskid = gjson.Get(string(s), string("taskId")).String()
	}

	if len(r.Form["cmdname"]) > 0 {
		cmdname = r.Form["cmdname"][0]
	} else {
		cmdname = gjson.Get(string(s), string("cmdname")).String()
	}

	if len(r.Form["conf"]) > 0 {
		conf = r.Form["conf"][0]
	} else {
		conf = gjson.Get(string(s), string("conf")).String()
	}

	if len(r.Form["identification"]) > 0 {
		omcconf = r.Form["identification"][0]
	} else {
		omcconf = gjson.Get(string(s), string("identification")).String()
	}

	if len(r.Form["hash"]) > 0 {
		hash = r.Form["hash"][0]
	} else {
		hash = gjson.Get(string(s), string("hash")).String()
	}

	//开始时间参数
	if len(r.Form["cmdp1"]) > 0 {
		cmdp1 = r.Form["cmdp1"][0]
	} else {
		cmdp1 = gjson.Get(string(s), string("cmdp1")).String()
	}

	if len(r.Form["dataUrl"]) > 0 {
		dataurl = r.Form["dataUrl"][0]
	} else {
		dataurl = gjson.Get(string(s), string("dataUrl")).String()
	}

	if len(r.Form["token"]) > 0 {
		token = r.Form["token"][0]
	} else {
		token = gjson.Get(string(s), string("token")).String()
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
	//结束时间参数
	if len(r.Form["cmdp2"]) > 0 {
		cmdp2 = r.Form["cmdp2"][0]
	} else {
		cmdp2 = gjson.Get(string(s), string("cmdp2")).String()
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
	} else {
		cmdp3 = gjson.Get(string(s), string("cmdp3")).String()
	}
	if len(r.Form["cmdp4"]) > 0 {
		cmdp4 = r.Form["cmdp4"][0]
	} else {
		cmdp4 = gjson.Get(string(s), string("cmdp4")).String()
	}

	if len(r.Form["user"]) > 0 {
		cmduser = r.Form["user"][0]
	} else {
		cmduser = gjson.Get(string(s), string("user")).String()
	}

	if len(r.Form["type"]) > 0 {
		cmdtype = r.Form["type"][0]
	} else {
		cmdtype = gjson.Get(string(s), string("type")).String()
	}

	data := gjson.Get(string(s), string("spc")).String()
	log.Println("收到的请求内容为:", data)

	//如果传参中配置了conf参数，就按照配置文件模板生成配置文件

	if conf != "" {

		targetType := gjson.Get(data, string("targetType")).String()
		if targetType == "1" {
			conf = "gptoftp.xml"
			cmdname = "gptoftp.sh"
		}
		if targetType == "0" {
			conf = "gptogp.xml"
			cmdname = "gptogp.sh"
		}
		if targetType == "2" {
			conf = "gptokafka.xml"
			cmdname = "gptokafka.sh"
		}
		if targetType == "3" {
			conf = "gptohdfs.xml"
			cmdname = "gptohdfs.sh"
		}

		//如果带f参数先删后更新

		reg := regexp.MustCompile(`{{[^}]+}}`)

		str, err := ioutil.ReadFile(conf + ".tmp")

		if err != nil {
			log.Println(err)
		}

		//获取参数后可以通过配置文件进行获取再次转发
		result := string(str)
		result = strings.ReplaceAll(result, "{{taskid}}", taskid)
		result = strings.ReplaceAll(result, "{{cmdp1}}", cmdp1)
		result = strings.ReplaceAll(result, "{{cmdp2}}", cmdp2)
		result = strings.ReplaceAll(result, "{{cmdp3}}", cmdp3)
		result = strings.ReplaceAll(result, "{{cmdp4}}", cmdp4)
		dataSlice := reg.FindAll(str, -1)
		for _, v := range dataSlice {
			//fmt.Println("vvvv:",string(v))
			aaaaaa = strings.ReplaceAll(string(v), "{", "")
			aaaaaa = strings.ReplaceAll(aaaaaa, "}", "")

			bbbbbb = gjson.Get(data, string(aaaaaa)).String()

			bbbbbb = strings.ReplaceAll(bbbbbb, "[", "")
			bbbbbb = strings.ReplaceAll(bbbbbb, "]", "")
			//bbbbbb = strings.ReplaceAll(bbbbbb, "\"", "")

			result = strings.ReplaceAll(result, string(v), bbbbbb)

		}

		//如果cmdname中为http请求，则调用api逻辑
		if cmdname[0:4] == "http" {

			log.Println("api:", cmdname, "body:", "\n", result)
			rep, err := httppost(r.Header.Get("token"), cmdname, result)
			if err != nil {
				log.Println(err)
				fmt.Fprintf(w, `{"taskid":"`+taskid+`","pid":-1,"filelog":"","status":false,"errinfo":`+err.Error()+`}`)
				return
			} else {
				fmt.Fprintf(w, rep)
				return
			}

		}

		ioutil.WriteFile(taskid+".xml", []byte(result), fs.FileMode(0777))

	}

	//如果收到的是omc采集配置文件信息，需要判断是否需要更新文件

	if omcconf != "" {
		if _, err := os.Stat("." + omcconf + "." + hash); err != nil {

			cfg, _ := httppost(token, dataurl+"?dentification="+omcconf+"&token="+token, "")
			result := MakeOmcConf(cfg)
			ioutil.WriteFile("config/datasource/"+omcconf, []byte(result), fs.FileMode(0777))

			ioutil.WriteFile("config/datasource/."+omcconf+"."+hash, []byte(hash), fs.FileMode(0777))
		}
	}

	switch cmdtype {
	case "xml":
		w.Header().Set("content-type", "text/xml; charset=utf-8")
	case "json":
		w.Header().Set("Content-Type", "text/json; charset=utf-8")
	default:
		w.Header().Set("content-type", "text/html; charset=utf-8")
	}

	fmt.Fprintf(w, getcmd(p, cmdname, cmdp1, cmdp2, cmdp3, cmdp4, cmdtype, cmduser, cmdname, taskid))

}

//根据返回的json创建omc配置xml

func MakeOmcConf(cfg string) string {

	//公共部分的模板
	str := `
	<?xml version="1.0" encoding="UTF-8"?>
	<DataSource>
		<!--省份 -->
		<province>{{province}}</province>
		<!-- 数据类型：pm|cm|fm -->
		<dataType>{{dataType}}</dataType>
		<!-- 网络类型：5gc|5gr|4gr|234gc -->
		<networkType>{{networkType}}</networkType>
		<!-- 厂家ID：hw|zte -->
		<vendorId>{{vendorId}}</vendorId>
		<!-- 版本：OMC北向接口指标数据集主版本（如果是厂家私有接口写厂家网管版本或设备型号） -->
		<version>{{version}}</version>
		<!-- OMCID -->
		<equipmentId>{{equipmentId}}</equipmentId>
		<equipmentType>{{equipmentType}}</equipmentType>
		<networkName>{{networkName}}</networkName>
		
		<!-- OUID（如果是分布式OMC，需要配置ouid做区分） -->
		<OUID>{{ouid}}</OUID>
		<!--数据周期，单位分钟 -->
		<dataPeriod>{{dataPeriod}}</dataPeriod>
		<delayThreshold>{{delayThreshold}}</delayThreshold>
		<resourceType>{{resourceType}}</resourceType>
		<region>{{region}}</region>
		<specialty>{{specialty}}</specialty>
		<!-- 采集输出数据共享配置的用户名，可以到config/share/shareConf.xml找对应用户的共享配置信息 -->
	   <flow>adaptation-equipmentInterface-ftp-sftp-1.0.jar,adaptation-Parser-csv-xml-json-1.0-full.jar,adaptation-calculation.jar,adaptation-shareInterface-hdfs-sftp-ftp.jar</flow> 
	 <!-- 	<flow>adaptation-equipmentInterface-restful.jar</flow> -->
		<shareUserName>{{shareUserName}}</shareUserName>
	
		`

	//ftp的模板
	str_ftp := `<!--采集源私有参数放在interfacePara标签下，适配器的各阶段程序都需要配置一个interfacePara。如果适配器各阶段程序不需要配置信息，则interfacePara可省略。interfacePara标签下，根据interfaceType区分处理阶段，主要包括三种：FTP-DownLoad、calculation、DB。 -->
		<!--ftp或sftp下载，interfaceType值固定写死："DownLoad" -->
		<interfacePara interfaceType="DownLoad">
		  <!--协议类型 sftp/ftp-->
		<protocolType>{{protocolType}}</protocolType>
		<!-- 数据源ip地址 -->
		 <ip>{{ip}}</ip>
		<!-- 数据源端口 -->
		 <port>{{port}}</port>
		<!-- 数据源用户名 -->
		 <username>{{userName}}</username>
		<!-- 数据源用户密码 -->
		 <password>{{password}}</password>
		<!-- 数据源文件路径（多个路径之间用英文分号隔开）-->
		<remotePath>
		{{remotePath}}
		</remotePath> 
		<!-- 是否需要重命名原始文件名。需要重命名：true;不需要：false(命名规则，文件目录中由括号括起来的部分_原始文件名，作为新文件名)
			重命名文件中需要拼接哪一级目录，写|目录级数（目录级别从后往前数，是第几级就写数字几）-->
		<renamefilename>{{renameFileName}}</renamefilename>
		<!-- 主被动模式(默认为被动模式为false，主动模式为：true) -->
		 <isPassive>{{isPassive}}</isPassive>
		<!-- 本地存储目录（如果是采集业务可置空，如果是文件搬移，需要配本地服务器文件存储路径）-->
		<!--置空，程序默认路径为：../DcpCollector/data/$[dataType]/$[networkType]/$[dataSourceName]/{getTime($[dataTime],yyyyMMddHHmm)}/$[taskId]/datasource/  -->
		<localPath>{{localPath}}</localPath>
		<!-- 下载超时时间(默认6000ms) -->
		<timeout>{{timeout}}</timeout>
		<!-- 是否开启增量扫描(true|false) -->
		<openScan>{{openScan}}</openScan>
		<!-- 是否需要解压(true|false) -->
		<decompress>{{decompress}}</decompress>
	   </interfacePara>
	   
	   `

	//数据库方式的模板
	str_db := `	
		  <!-- 配置从数据来源库取数据的interfaceType，固定写法DB -->
		<interfacePara interfaceType="DB">
		  <!--单次任务输出文件个数-->
		  <fileOutCount>{{fileOutCount}}</fileOutCount>
		  <!--数据库类型（1、sybase 2、mysql 3、oracle 4 sqlserver 5、gp）-->
		  <dbType>{{dbType}}</dbType>
		  <!--数据库ip-->
		  <ip>{{ip}}</ip>
		  <!--数据库端口-->
		  <port>{{port}}</port>
		  <!--数据库名称-->
		  <dbName>{{dbName}}</dbName>
		  <!--数据库登录用户-->
		<userName>{{userName}}</userName>
		  <!--数据库登录用户密码-->
		  <passWord>{{password}}</passWord>
		  <!--数据分隔符-->
		  <separator>{{separators}}</separator>
		  <shareUserName>{{shareUserName}}</shareUserName>
		</interfacePara>
		
		`
	//获取一个源数据json数组
	var omccofig OmcCfg

	json.Unmarshal([]byte(cfg), &omccofig)

	//公共部分
	result := json2str(str, omccofig.Rows[0])

	for i := 0; i < len(omccofig.Rows); i++ {
		if omccofig.Rows[i]["protocolType"].(string) == "jdbc" {
			result += json2str(str_db, omccofig.Rows[i])
		}
		if omccofig.Rows[i]["protocolType"].(string) == "ftp" || omccofig.Rows[i]["protocolType"].(string) == "sftp" {
			result += json2str(str_ftp, omccofig.Rows[i])
		}
	}

	return result + `</DataSource>`
}

//可以通过传送一个数据和模板，可以自动根据模板中的标识进行数据替换
//str= <aaa>{{aaa}}</aaa>   map="aaa":12345  result=<aaa>12345</aaa>

func json2str(str string, omc map[string]interface{}) string {
	reg := regexp.MustCompile(`{{[^}]+}}`)
	result := str
	dataSlice := reg.FindAll([]byte(str), -1)
	for _, v := range dataSlice {

		aaaaaa := strings.ReplaceAll(string(v), "{", "")
		aaaaaa = strings.ReplaceAll(aaaaaa, "}", "")

		bbbbbb := omc[aaaaaa]

		switch bbbbbb.(type) {
		case string:
			op, ok := bbbbbb.(string)
			if ok {
				result = strings.ReplaceAll(result, string(v), fmt.Sprintf("%v", op))
			}
		case float64:
			op, ok := bbbbbb.(float64)
			if ok {
				result = strings.ReplaceAll(result, string(v), fmt.Sprintf("%v", op))
			}
		case int64:
			op, ok := bbbbbb.(int64)
			if ok {
				result = strings.ReplaceAll(result, string(v), fmt.Sprintf("%v", op))
			}
		default:
		}
	}
	return result
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
		fmt.Printf("build ver:\t%s\n", "20220321")

		os.Exit(0)
	}

	var one sync.Mutex
	mux := &MyMux{token, 0, 0, one, cpulimit, memlimit}
	go setsystem(mux)
	log.Println("dcpnode starting,port:", port)
	err := http.ListenAndServe(":"+port, mux)
	if err != nil {
		log.Println("dcpnode start err:", err)
	}

}
