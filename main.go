package main

import (
	"bufio"
	"context"
	"fmt"
	"math/rand"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	core2 "github.com/boy-hack/ksubdomain/v2/pkg/core"
	"github.com/boy-hack/ksubdomain/v2/pkg/core/ns"
	"github.com/boy-hack/ksubdomain/v2/pkg/core/options"
	"github.com/boy-hack/ksubdomain/v2/pkg/runner"
	"github.com/boy-hack/ksubdomain/v2/pkg/runner/outputter"
	output2 "github.com/boy-hack/ksubdomain/v2/pkg/runner/outputter/output"
	"github.com/boy-hack/ksubdomain/v2/pkg/runner/processbar"
	"github.com/boy-hack/ksubdomain/v2/pkg/runner/result"
)

type GUIProcess struct {
	statusLabel  *widget.Label
	resultList   *widget.List
	results      []string
	lock         chan struct{}
	mu           sync.Mutex
	deviceInfo   string
	totalDomains int
	processed    int
	maxProgress  float64
}
type GUIProcessBar struct {
	guiProcess *GUIProcess
}

func (g *GUIProcessBar) WriteData(data *processbar.ProcessData) {
	g.guiProcess.UpdateStatus(
		int(data.SuccessIndex),
		int(data.SendIndex),
		int(data.QueueLength),
		int(data.RecvIndex),
		int(data.FaildIndex),
		data.Elapsed,
	)
}
func (g *GUIProcessBar) Close() {
}
func NewGUIProcess(statusLabel *widget.Label, resultList *widget.List) *GUIProcess {
	return &GUIProcess{
		statusLabel:  statusLabel,
		resultList:   resultList,
		results:      make([]string, 0),
		lock:         make(chan struct{}, 1),
		deviceInfo:   "",
		totalDomains: 0,
		processed:    0,
		maxProgress:  0,
	}
}
func (g *GUIProcess) UpdateStatus(successCount, sendCount, queueLength, recvCount, failCount, elapsed int) {
	g.processed = successCount
	var progressPercent float64 = 0
	if g.totalDomains > 0 {
		progressPercent = float64(successCount) / float64(g.totalDomains) * 100
		if progressPercent > 100 {
			progressPercent = 100
		}
	}
	statusText := fmt.Sprintf("成功: %d | 发送: %d | 队列: %d | 接收: %d | 失败: %d | 用时: %ds | 进度: %.2f%%",
		successCount, sendCount, queueLength, recvCount, failCount, elapsed, progressPercent)
	if g.deviceInfo != "" {
		statusText += " | " + g.deviceInfo
	}
	g.statusLabel.SetText(statusText)
}
func (g *GUIProcess) SetDeviceInfo(info string) {
	g.mu.Lock()
	g.deviceInfo = info
	g.mu.Unlock()
}
func (g *GUIProcess) Close() {
}
func (g *GUIProcess) AddResult(result string) {
	select {
	case g.lock <- struct{}{}:
		g.results = append(g.results, result)
		g.resultList.Refresh()
		<-g.lock
	default:
	}
}
func (g *GUIProcess) SetTotalDomains(total int) {
	g.mu.Lock()
	g.totalDomains = total
	g.mu.Unlock()
}
func (g *GUIProcess) UpdateTotalDomains(newTotal int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	var currentProgress float64 = 0
	if g.totalDomains > 0 {
		currentProgress = float64(g.processed) / float64(g.totalDomains)
	}
	if newTotal > g.totalDomains {
		g.totalDomains = newTotal
		if g.totalDomains > 0 {
			g.maxProgress = currentProgress
		}
	}
}

type GUIOutput struct {
	process     *GUIProcess
	filterMode  string
	wildIps     []string
	knownDomain map[string]struct{}
	predictMode bool
}

func NewGUIOutput(process *GUIProcess, filterMode string, predictMode bool) *GUIOutput {
	return &GUIOutput{
		process:     process,
		filterMode:  filterMode,
		knownDomain: make(map[string]struct{}),
		predictMode: predictMode,
	}
}
func (g *GUIOutput) WriteDomainResult(domain result.Result) error {
	return g.Write(domain.Subdomain, domain.Answers)
}
func (g *GUIOutput) Write(domain string, ips []string) error {
	if g.filterMode != "none" && len(g.wildIps) > 0 {
		if g.filterMode == "basic" {
			for _, ip := range ips {
				for _, wildip := range g.wildIps {
					if ip == wildip {
						return nil
					}
				}
			}
		}
		if g.filterMode == "advanced" {
			for _, ip := range ips {
				ipPrefix := strings.Join(strings.Split(ip, ".")[:3], ".")
				for _, wildip := range g.wildIps {
					wildPrefix := strings.Join(strings.Split(wildip, ".")[:3], ".")
					if ipPrefix == wildPrefix {
						return nil
					}
				}
			}
		}
	}
	if _, ok := g.knownDomain[domain]; ok {
		return nil
	}
	g.knownDomain[domain] = struct{}{}
	result := fmt.Sprintf("%s [%s]", domain, strings.Join(ips, ","))
	g.process.AddResult(result)
	return nil
}
func (g *GUIOutput) Close() error {
	return nil
}
func (g *GUIOutput) SetWildcardIps(ips []string) {
	g.wildIps = ips
}
func main() {
	a := app.New()
	a.Settings().SetTheme(theme.LightTheme())
	w := a.NewWindow("KSubdomain GUI - 极速无状态子域名爆破工具")
	w.Resize(fyne.NewSize(900, 600))
	tabs := container.NewAppTabs(
		container.NewTabItem("枚举模式", createEnumTab(w)),
		container.NewTabItem("验证模式", createVerifyTab(w)),
		container.NewTabItem("关于", createAboutTab()),
	)
	tabs.SetTabLocation(container.TabLocationTop)
	w.SetContent(tabs)
	w.ShowAndRun()
}
func createEnumTab(window fyne.Window) fyne.CanvasObject {
	domainEntry := widget.NewEntry()
	domainEntry.SetPlaceHolder("输入域名，多个域名用逗号分隔")
	domainListEntry := widget.NewEntry()
	domainListEntry.SetPlaceHolder("可选: 域名列表文件路径")
	dictEntry := widget.NewEntry()
	dictEntry.SetPlaceHolder("可选: 字典文件路径")
	resolversEntry := widget.NewEntry()
	resolversEntry.SetPlaceHolder("可选: DNS服务器，多个用逗号分隔")
	outputEntry := widget.NewEntry()
	outputEntry.SetPlaceHolder("可选: 输出文件路径")
	bandwidthEntry := widget.NewEntry()
	bandwidthEntry.SetText("5")
	bandwidthEntry.SetPlaceHolder("带宽限制")
	bandwidthContainer := container.NewHBox(widget.NewLabel("带宽限制:"), bandwidthEntry, widget.NewLabel("M"))
	retryEntry := widget.NewEntry()
	retryEntry.SetText("3")
	retryEntry.SetPlaceHolder("重试次数")
	timeoutEntry := widget.NewEntry()
	timeoutEntry.SetText("6")
	timeoutEntry.SetPlaceHolder("超时(秒)")
	nsCheck := widget.NewCheck("读取域名NS记录并加入到解析器中", nil)
	predictCheck := widget.NewCheck("启用预测域名模式", nil)
	wildcardFilterSelect := widget.NewSelect([]string{"none", "basic", "advanced"}, nil)
	wildcardFilterSelect.SetSelected("none")
	wildcardFilterSelect.PlaceHolder = "泛解析过滤"
	outputTypeSelect := widget.NewSelect([]string{"txt", "json", "csv"}, nil)
	outputTypeSelect.SetSelected("txt")
	outputTypeSelect.PlaceHolder = "输出格式"
	advancedOptionsRow := container.NewHBox(
		bandwidthContainer,
		widget.NewLabel("    重试:"),
		retryEntry,
		widget.NewLabel("    超时:"),
		timeoutEntry,
		widget.NewLabel("    泛解析过滤:"),
		wildcardFilterSelect,
		widget.NewLabel("    输出格式:"),
		outputTypeSelect,
	)
	resultsList := widget.NewList(
		func() int {
			return 0
		},
		func() fyne.CanvasObject {
			return widget.NewLabel("")
		},
		func(id widget.ListItemID, obj fyne.CanvasObject) {
		},
	)
	resultBorder := canvas.NewRectangle(theme.BackgroundColor())
	resultBorder.StrokeColor = theme.PrimaryColor()
	resultBorder.StrokeWidth = 2
	resultContainer := container.NewMax(
		resultBorder,
		container.NewPadded(container.NewPadded(resultsList)),
	)
	statusLabel := widget.NewLabel("就绪")
	statusLabel.Alignment = fyne.TextAlignCenter
	openDictButton := widget.NewButtonWithIcon("打开", theme.FolderOpenIcon(), func() {
		fd := dialog.NewFileOpen(func(reader fyne.URIReadCloser, err error) {
			if err != nil {
				dialog.ShowError(err, window)
				return
			}
			if reader == nil {
				return
			}
			dictEntry.SetText(reader.URI().Path())
		}, window)
		fd.Show()
	})
	openDomainListButton := widget.NewButtonWithIcon("打开", theme.FolderOpenIcon(), func() {
		fd := dialog.NewFileOpen(func(reader fyne.URIReadCloser, err error) {
			if err != nil {
				dialog.ShowError(err, window)
				return
			}
			if reader == nil {
				return
			}
			domainListEntry.SetText(reader.URI().Path())
		}, window)
		fd.Show()
	})
	setOutputButton := widget.NewButtonWithIcon("设置", theme.DocumentSaveIcon(), func() {
		fd := dialog.NewFileSave(func(writer fyne.URIWriteCloser, err error) {
			if err != nil {
				dialog.ShowError(err, window)
				return
			}
			if writer == nil {
				return
			}
			outputEntry.SetText(writer.URI().Path())
		}, window)
		fd.Show()
	})
	var cancelFunc context.CancelFunc = nil
	var startButton *widget.Button
	startButton = widget.NewButtonWithIcon("开始枚举", theme.MediaPlayIcon(), func() {
		domainText := domainEntry.Text
		domainListFile := domainListEntry.Text
		if domainText == "" && domainListFile == "" {
			dialog.ShowError(fmt.Errorf("请输入目标域名或域名列表文件"), window)
			return
		}
		bandwidthStr := bandwidthEntry.Text + "m"
		if bandwidthEntry.Text == "" {
			bandwidthStr = "5m"
		} else {
			if _, err := strconv.Atoi(bandwidthEntry.Text); err != nil {
				dialog.ShowError(fmt.Errorf("带宽必须是数字，单位为M"), window)
				return
			}
		}
		var domains []string
		if domainText != "" {
			for _, d := range strings.Split(domainText, ",") {
				domains = append(domains, strings.TrimSpace(d))
			}
		}
		if domainListFile != "" {
			f, err := os.Open(domainListFile)
			if err != nil {
				dialog.ShowError(fmt.Errorf("打开域名文件出错: %s", err), window)
				return
			}
			defer f.Close()
			scanner := bufio.NewScanner(f)
			for scanner.Scan() {
				domain := strings.TrimSpace(scanner.Text())
				if domain != "" {
					domains = append(domains, domain)
				}
			}
			if err := scanner.Err(); err != nil {
				dialog.ShowError(fmt.Errorf("读取域名文件出错: %s", err), window)
				return
			}
		}
		if len(domains) == 0 {
			dialog.ShowError(fmt.Errorf("未找到有效的目标域名"), window)
			return
		}
		guiProcess := NewGUIProcess(statusLabel, resultsList)
		resultsList.Length = func() int {
			return len(guiProcess.results)
		}
		resultsList.UpdateItem = func(id widget.ListItemID, obj fyne.CanvasObject) {
			if id < len(guiProcess.results) {
				obj.(*widget.Label).SetText(guiProcess.results[id])
			}
		}
		var writer []outputter.Output
		guiOutput := NewGUIOutput(guiProcess, wildcardFilterSelect.Selected, predictCheck.Checked)
		writer = append(writer, guiOutput)
		if outputEntry.Text != "" {
			outputFile := outputEntry.Text
			outputType := outputTypeSelect.Selected
			wildFilterMode := wildcardFilterSelect.Selected
			switch outputType {
			case "txt":
				p, err := output2.NewPlainOutput(outputFile, wildFilterMode)
				if err != nil {
					dialog.ShowError(err, window)
					return
				}
				writer = append(writer, p)
			case "json":
				p := output2.NewJsonOutput(outputFile, wildFilterMode)
				writer = append(writer, p)
			case "csv":
				p := output2.NewCsvOutput(outputFile, wildFilterMode)
				writer = append(writer, p)
			}
		}
		var resolvers []string
		if resolversEntry.Text != "" {
			for _, r := range strings.Split(resolversEntry.Text, ",") {
				resolvers = append(resolvers, strings.TrimSpace(r))
			}
		}
		wildIPS := make([]string, 0)
		if wildcardFilterSelect.Selected != "none" {
			for _, sub := range domains {
				ok, ips := runner.IsWildCard(sub)
				if ok {
					wildIPS = append(wildIPS, ips...)
					statusLabel.SetText(fmt.Sprintf("发现泛解析域名: %s", sub))
				}
			}
			guiOutput.SetWildcardIps(wildIPS)
		}
		specialDns := make(map[string][]string)
		defaultResolver := options.GetResolvers(resolvers)
		if nsCheck.Checked {
			for _, domain := range domains {
				nsServers, ips, err := ns.LookupNS(domain, defaultResolver[rand.Intn(len(defaultResolver))])
				if err != nil {
					continue
				}
				specialDns[domain] = ips
				statusLabel.SetText(fmt.Sprintf("%s ns: %v", domain, nsServers))
			}
		}
		render := make(chan string)
		go func() {
			filename := dictEntry.Text
			if filename == "" {
				subdomainDict := core2.GetDefaultSubdomainData()
				var totalDomains int
				totalDomains = len(subdomainDict) * len(domains)
				guiProcess.SetTotalDomains(totalDomains)
				for _, domain := range domains {
					for _, sub := range subdomainDict {
						dd := sub + "." + domain
						render <- dd
					}
				}
			} else {
				f2, err := os.Open(filename)
				if err != nil {
					dialog.ShowError(fmt.Errorf("打开文件出错: %s", err), window)
					return
				}
				defer f2.Close()
				iofile := bufio.NewScanner(f2)
				iofile.Split(bufio.ScanLines)
				lineCount := 0
				for iofile.Scan() {
					lineCount++
				}
				f2.Seek(0, 0)
				iofile = bufio.NewScanner(f2)
				iofile.Split(bufio.ScanLines)
				totalDomains := lineCount * len(domains)
				guiProcess.SetTotalDomains(totalDomains)
				for iofile.Scan() {
					sub := iofile.Text()
					for _, domain := range domains {
						render <- sub + "." + domain
					}
				}
			}
			close(render)
		}()
		retry := 3
		if retryEntry.Text != "" {
			fmt.Sscanf(retryEntry.Text, "%d", &retry)
		}
		timeout := 6
		if timeoutEntry.Text != "" {
			fmt.Sscanf(timeoutEntry.Text, "%d", &timeout)
		}
		loadingProgress := dialog.NewProgress("正在准备扫描", "正在配置网络设备...", window)
		loadingProgress.Show()
		startButton.Disable()
		startButton.SetText("扫描中...")
		statusLabel.SetText("正在准备扫描...")
		var ctx context.Context
		ctx, cancelFunc = context.WithCancel(context.Background())
		go func() {
			opt := &options.Options{
				Rate:               options.Band2Rate(bandwidthStr),
				Domain:             render,
				Resolvers:          defaultResolver,
				Silent:             false,
				TimeOut:            timeout,
				Retry:              retry,
				Method:             options.EnumType,
				Writer:             writer,
				SpecialResolvers:   specialDns,
				WildcardFilterMode: wildcardFilterSelect.Selected,
				WildIps:            wildIPS,
				Predict:            predictCheck.Checked,
				ProcessBar:         &GUIProcessBar{guiProcess: guiProcess},
			}
			opt.Check()
			loadingProgress.SetValue(0.5)
			opt.EtherInfo = options.GetDeviceConfig(defaultResolver)
			if opt.EtherInfo != nil {
				deviceInfo := fmt.Sprintf("网卡: %s, IP: %s", opt.EtherInfo.Device, opt.EtherInfo.SrcIp)
				guiProcess.SetDeviceInfo(deviceInfo)
			}
			loadingProgress.Hide()
			statusLabel.SetText("正在扫描...")
			r, err := runner.New(opt)
			if err != nil {
				dialog.ShowError(fmt.Errorf("创建扫描器失败: %s", err), window)
				startButton.Enable()
				startButton.SetText("开始枚举")
				cancelFunc = nil
				return
			}
			if predictCheck.Checked {
				predictionMonitor := time.NewTicker(3 * time.Second)
				go func() {
					defer predictionMonitor.Stop()
					lastProcessed := 0
					for {
						select {
						case <-ctx.Done():
							return
						case <-predictionMonitor.C:
							if guiProcess.processed > lastProcessed {
								currentEstimate := guiProcess.processed + 100
								if currentEstimate > guiProcess.totalDomains {
									guiProcess.UpdateTotalDomains(currentEstimate)
								}
								lastProcessed = guiProcess.processed
							}
						}
					}
				}()
			}
			defer func() {
				r.Close()
				startButton.Enable()
				startButton.SetText("开始枚举")
				cancelFunc = nil
				statusLabel.SetText("扫描完成")
			}()
			r.RunEnumeration(ctx)
		}()
	})
	stopButton := widget.NewButtonWithIcon("停止扫描", theme.MediaStopIcon(), func() {
		if cancelFunc != nil {
			cancelFunc()
			statusLabel.SetText("扫描已停止")
			startButton.Enable()
			startButton.SetText("开始枚举")
			cancelFunc = nil
		}
	})
	form := &widget.Form{
		Items: []*widget.FormItem{
			{Text: "目标域名", Widget: domainEntry, HintText: "可选，支持多个域名，用逗号分隔"},
			{Text: "域名列表文件", Widget: container.NewBorder(nil, nil, nil, openDomainListButton, domainListEntry), HintText: "可选，从文件读取目标域名列表"},
			{Text: "字典文件", Widget: container.NewBorder(nil, nil, nil, openDictButton, dictEntry), HintText: "可选，不填使用内置字典"},
			{Text: "DNS服务器", Widget: resolversEntry, HintText: "可选，不填使用默认DNS"},
			{Text: "输出文件", Widget: container.NewBorder(nil, nil, nil, setOutputButton, outputEntry), HintText: "可选，设置结果保存位置"},
			{Text: "选项设置", Widget: advancedOptionsRow, HintText: "设置带宽限制、重试次数、超时、过滤模式和输出格式"},
		},
	}
	optionsFrame := container.NewVBox(
		container.NewCenter(
			container.NewHBox(
				nsCheck,
				widget.NewLabel("    "),
				predictCheck,
			),
		),
	)
	buttons := container.NewCenter(
		container.NewHBox(
			startButton,
			widget.NewSeparator(),
			stopButton,
		),
	)
	statusContainer := container.NewVBox(
		statusLabel,
	)
	return container.NewBorder(
		container.NewVBox(
			container.NewPadded(container.NewPadded()),
			form,
			container.NewPadded(widget.NewSeparator()),
			optionsFrame,
			container.NewPadded(buttons),
			container.NewPadded(statusContainer),
		),
		nil,
		nil,
		nil,
		resultContainer,
	)
}
func createVerifyTab(window fyne.Window) fyne.CanvasObject {
	domainEntry := widget.NewEntry()
	domainEntry.SetPlaceHolder("输入域名，多个域名用逗号分隔")
	domainListEntry := widget.NewEntry()
	domainListEntry.SetPlaceHolder("可选: 域名列表文件路径")
	resolversEntry := widget.NewEntry()
	resolversEntry.SetPlaceHolder("可选: DNS服务器，多个用逗号分隔")
	outputEntry := widget.NewEntry()
	outputEntry.SetPlaceHolder("可选: 输出文件路径")
	bandwidthEntry := widget.NewEntry()
	bandwidthEntry.SetText("5")
	bandwidthEntry.SetPlaceHolder("带宽限制")
	bandwidthContainer := container.NewHBox(widget.NewLabel("带宽限制:"), bandwidthEntry, widget.NewLabel("M"))
	retryEntry := widget.NewEntry()
	retryEntry.SetText("3")
	retryEntry.SetPlaceHolder("重试次数")
	timeoutEntry := widget.NewEntry()
	timeoutEntry.SetText("6")
	timeoutEntry.SetPlaceHolder("超时(秒)")
	predictCheck := widget.NewCheck("启用预测域名模式", nil)
	wildcardFilterSelect := widget.NewSelect([]string{"none", "basic", "advanced"}, nil)
	wildcardFilterSelect.SetSelected("none")
	wildcardFilterSelect.PlaceHolder = "泛解析过滤"
	outputTypeSelect := widget.NewSelect([]string{"txt", "json", "csv"}, nil)
	outputTypeSelect.SetSelected("txt")
	outputTypeSelect.PlaceHolder = "输出格式"
	advancedOptionsRow := container.NewHBox(
		bandwidthContainer,
		widget.NewLabel("    重试:"),
		retryEntry,
		widget.NewLabel("    超时:"),
		timeoutEntry,
		widget.NewLabel("    泛解析过滤:"),
		wildcardFilterSelect,
		widget.NewLabel("    输出格式:"),
		outputTypeSelect,
	)
	resultsList := widget.NewList(
		func() int {
			return 0
		},
		func() fyne.CanvasObject {
			return widget.NewLabel("")
		},
		func(id widget.ListItemID, obj fyne.CanvasObject) {
		},
	)
	resultBorder := canvas.NewRectangle(theme.BackgroundColor())
	resultBorder.StrokeColor = theme.PrimaryColor()
	resultBorder.StrokeWidth = 2
	resultContainer := container.NewMax(
		resultBorder,
		container.NewPadded(container.NewPadded(resultsList)),
	)
	statusLabel := widget.NewLabel("就绪")
	statusLabel.Alignment = fyne.TextAlignCenter
	openDomainListButton := widget.NewButtonWithIcon("打开", theme.FolderOpenIcon(), func() {
		fd := dialog.NewFileOpen(func(reader fyne.URIReadCloser, err error) {
			if err != nil {
				dialog.ShowError(err, window)
				return
			}
			if reader == nil {
				return
			}
			domainListEntry.SetText(reader.URI().Path())
		}, window)
		fd.Show()
	})
	setOutputButton := widget.NewButtonWithIcon("设置", theme.DocumentSaveIcon(), func() {
		fd := dialog.NewFileSave(func(writer fyne.URIWriteCloser, err error) {
			if err != nil {
				dialog.ShowError(err, window)
				return
			}
			if writer == nil {
				return
			}
			outputEntry.SetText(writer.URI().Path())
		}, window)
		fd.Show()
	})
	var cancelFunc context.CancelFunc = nil
	var startButton *widget.Button
	startButton = widget.NewButtonWithIcon("开始验证", theme.MediaPlayIcon(), func() {
		domainText := domainEntry.Text
		domainListFile := domainListEntry.Text
		if domainText == "" && domainListFile == "" {
			dialog.ShowError(fmt.Errorf("请输入目标域名或域名列表文件"), window)
			return
		}
		bandwidthStr := bandwidthEntry.Text + "m"
		if bandwidthEntry.Text == "" {
			bandwidthStr = "5m"
		} else {
			if _, err := strconv.Atoi(bandwidthEntry.Text); err != nil {
				dialog.ShowError(fmt.Errorf("带宽必须是数字，单位为M"), window)
				return
			}
		}
		var domains []string
		if domainText != "" {
			for _, d := range strings.Split(domainText, ",") {
				domains = append(domains, strings.TrimSpace(d))
			}
		}
		guiProcess := NewGUIProcess(statusLabel, resultsList)
		resultsList.Length = func() int {
			return len(guiProcess.results)
		}
		resultsList.UpdateItem = func(id widget.ListItemID, obj fyne.CanvasObject) {
			if id < len(guiProcess.results) {
				obj.(*widget.Label).SetText(guiProcess.results[id])
			}
		}
		var writer []outputter.Output
		guiOutput := NewGUIOutput(guiProcess, wildcardFilterSelect.Selected, predictCheck.Checked)
		writer = append(writer, guiOutput)
		if outputEntry.Text != "" {
			outputFile := outputEntry.Text
			outputType := outputTypeSelect.Selected
			wildFilterMode := wildcardFilterSelect.Selected
			switch outputType {
			case "txt":
				p, err := output2.NewPlainOutput(outputFile, wildFilterMode)
				if err != nil {
					dialog.ShowError(err, window)
					return
				}
				writer = append(writer, p)
			case "json":
				p := output2.NewJsonOutput(outputFile, wildFilterMode)
				writer = append(writer, p)
			case "csv":
				p := output2.NewCsvOutput(outputFile, wildFilterMode)
				writer = append(writer, p)
			}
		}
		var resolvers []string
		if resolversEntry.Text != "" {
			for _, r := range strings.Split(resolversEntry.Text, ",") {
				resolvers = append(resolvers, strings.TrimSpace(r))
			}
		}
		wildIPS := make([]string, 0)
		if wildcardFilterSelect.Selected != "none" {
			for _, sub := range domains {
				ok, ips := runner.IsWildCard(sub)
				if ok {
					wildIPS = append(wildIPS, ips...)
					statusLabel.SetText(fmt.Sprintf("发现泛解析域名: %s", sub))
				}
			}
			guiOutput.SetWildcardIps(wildIPS)
		}
		render := make(chan string)
		go func() {
			var totalDomains int
			totalDomains += len(domains)
			for _, domain := range domains {
				render <- domain
			}
			if domainListFile != "" {
				f2, err := os.Open(domainListFile)
				if err != nil {
					dialog.ShowError(fmt.Errorf("打开文件出错: %s", err), window)
					return
				}
				defer f2.Close()
				lineCount := 0
				iofile := bufio.NewScanner(f2)
				iofile.Split(bufio.ScanLines)
				for iofile.Scan() {
					lineCount++
				}
				totalDomains += lineCount
				f2.Seek(0, 0)
				iofile = bufio.NewScanner(f2)
				iofile.Split(bufio.ScanLines)
				guiProcess.SetTotalDomains(totalDomains)
				for iofile.Scan() {
					render <- iofile.Text()
				}
			} else {
				guiProcess.SetTotalDomains(totalDomains)
			}
			close(render)
		}()
		retry := 3
		if retryEntry.Text != "" {
			fmt.Sscanf(retryEntry.Text, "%d", &retry)
		}
		timeout := 6
		if timeoutEntry.Text != "" {
			fmt.Sscanf(timeoutEntry.Text, "%d", &timeout)
		}
		loadingProgress := dialog.NewProgress("正在准备扫描", "正在配置网络设备...", window)
		loadingProgress.Show()
		startButton.Disable()
		startButton.SetText("验证中...")
		statusLabel.SetText("正在准备验证...")
		var ctx context.Context
		ctx, cancelFunc = context.WithCancel(context.Background())
		go func() {
			resolver := options.GetResolvers(resolvers)
			opt := &options.Options{
				Rate:               options.Band2Rate(bandwidthStr),
				Domain:             render,
				Resolvers:          resolver,
				Silent:             false,
				TimeOut:            timeout,
				Retry:              retry,
				Method:             options.VerifyType,
				Writer:             writer,
				WildcardFilterMode: wildcardFilterSelect.Selected,
				WildIps:            wildIPS,
				Predict:            predictCheck.Checked,
				ProcessBar:         &GUIProcessBar{guiProcess: guiProcess},
			}
			opt.Check()
			loadingProgress.SetValue(0.5)
			opt.EtherInfo = options.GetDeviceConfig(resolver)
			if opt.EtherInfo != nil {
				deviceInfo := fmt.Sprintf("网卡: %s, IP: %s", opt.EtherInfo.Device, opt.EtherInfo.SrcIp)
				guiProcess.SetDeviceInfo(deviceInfo)
			}
			loadingProgress.Hide()
			statusLabel.SetText("正在验证...")
			r, err := runner.New(opt)
			if err != nil {
				dialog.ShowError(fmt.Errorf("创建验证器失败: %s", err), window)
				startButton.Enable()
				startButton.SetText("开始验证")
				cancelFunc = nil
				return
			}
			if predictCheck.Checked {
				predictionMonitor := time.NewTicker(3 * time.Second)
				go func() {
					defer predictionMonitor.Stop()
					lastProcessed := 0
					for {
						select {
						case <-ctx.Done():
							return
						case <-predictionMonitor.C:
							if guiProcess.processed > lastProcessed {
								currentEstimate := guiProcess.processed + 100
								if currentEstimate > guiProcess.totalDomains {
									guiProcess.UpdateTotalDomains(currentEstimate)
								}
								lastProcessed = guiProcess.processed
							}
						}
					}
				}()
			}
			defer func() {
				r.Close()
				startButton.Enable()
				startButton.SetText("开始验证")
				cancelFunc = nil
				statusLabel.SetText("验证完成")
			}()
			r.RunEnumeration(ctx)
		}()
	})
	stopButton := widget.NewButtonWithIcon("停止验证", theme.MediaStopIcon(), func() {
		if cancelFunc != nil {
			cancelFunc()
			statusLabel.SetText("验证已停止")
			startButton.Enable()
			startButton.SetText("开始验证")
			cancelFunc = nil
		}
	})
	form := &widget.Form{
		Items: []*widget.FormItem{
			{Text: "目标域名", Widget: domainEntry, HintText: "可选，支持多个域名，用逗号分隔"},
			{Text: "域名列表文件", Widget: container.NewBorder(nil, nil, nil, openDomainListButton, domainListEntry), HintText: "可选，从文件读取待验证域名"},
			{Text: "DNS服务器", Widget: resolversEntry, HintText: "可选，不填使用默认DNS"},
			{Text: "输出文件", Widget: container.NewBorder(nil, nil, nil, setOutputButton, outputEntry), HintText: "可选，设置结果保存位置"},
			{Text: "选项设置", Widget: advancedOptionsRow, HintText: "设置带宽限制、重试次数、超时、过滤模式和输出格式"},
		},
	}
	optionsFrame := container.NewVBox(
		container.NewCenter(
			container.NewHBox(
				predictCheck,
			),
		),
	)
	buttons := container.NewCenter(
		container.NewHBox(
			startButton,
			widget.NewSeparator(),
			stopButton,
		),
	)
	resultTitleContainer := container.NewHBox(
		widget.NewIcon(theme.ListIcon()),
		widget.NewLabelWithStyle("验证结果", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
	)
	statusContainer := container.NewVBox(
		statusLabel,
	)
	return container.NewBorder(
		container.NewVBox(
			container.NewPadded(container.NewPadded()),
			form,
			container.NewPadded(widget.NewSeparator()),
			optionsFrame,
			container.NewPadded(buttons),
			container.NewPadded(resultTitleContainer),
			container.NewPadded(statusContainer),
		),
		nil,
		nil,
		nil,
		resultContainer,
	)
}
func createAboutTab() fyne.CanvasObject {
	logo := canvas.NewText("KSubdomain-GUI", theme.PrimaryColor())
	logo.TextSize = 24
	logo.TextStyle = fyne.TextStyle{Bold: true}
	version := widget.NewLabel("版本: 2.3.1")
	version.Alignment = fyne.TextAlignCenter
	description := widget.NewLabel("KSubdomain 是一款基于无状态技术的子域名爆破工具，带来前所未有的扫描速度和极低的内存占用。\n" +
		"这个GUI版本保留了原命令行工具的所有功能，同时提供了更友好的用户界面。\n" +
		"原项目地址：https://github.com/boy-hack/ksubdomain")
	description.Wrapping = fyne.TextWrapWord
	features := widget.NewLabel("核心优势:\n" +
		"• 闪电般的速度: 采用无状态扫描技术\n" +
		"• 极低的资源消耗: 创新的内存管理机制\n" +
		"• 无状态设计: 类似 Masscan 的无状态扫描\n" +
		"• 可靠的重发: 内建智能重发机制\n" +
		"• 跨平台支持: 完美兼容 Windows, Linux, macOS\n" +
		"• 易于使用: 简洁的图形界面\n" +
		"• 公众号：棉花糖fans")
	features.Wrapping = fyne.TextWrapWord
	githubURL, _ := url.Parse("https://github.com/mhtsec/ksubdomain-gui")
	githubLink := widget.NewHyperlink("访问 KSubdomain-GUI GitHub 项目", githubURL)
	descriptionCard := widget.NewCard("工具描述", "", description)
	featuresCard := widget.NewCard("功能特点", "", features)
	content := container.NewVBox(
		container.NewCenter(logo),
		container.NewCenter(version),
		container.NewPadded(descriptionCard),
		container.NewPadded(featuresCard),
		container.NewCenter(container.NewPadded(githubLink)),
	)
	return container.NewScroll(content)
}
