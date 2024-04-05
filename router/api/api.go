package api

import (
	"encoding/base64"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"vmq-go/db"
	"vmq-go/middleware"
	"vmq-go/router/api/admin"
	"vmq-go/task"
	"vmq-go/utils"
	"vmq-go/utils/captcha"
	"vmq-go/utils/hash"
	"vmq-go/utils/qrcode"

	"github.com/gin-gonic/gin"
)

// 初始化路由
func InitRouter(route *gin.Engine) {
	routeGroup := route.Group("/api")
	// 兼容djk
	routeGroup.GET("/createOrder", createOrderGETHandler)
	// 创建订单
	routeGroup.POST("/order", creatOrderHandler)
	// qrcode
	routeGroup.GET("/qrcode", qrcodeGetHandler)
	routeGroup.Use(middleware.JSONMiddleware())
	admin.SetupAdminRoutes(routeGroup)
	// 解析二维码
	routeGroup.POST("/qrcode", qrcodePostHandler)
	// 查询订单状态
	routeGroup.GET("/order/:orderId/state", getOrderStateGetHandler)
	// 验证码
	routeGroup.GET("/captcha", captchaHandler)
	// 心跳
	routeGroup.GET("/appHeart", HeartHandler)
	// 收到推送
	routeGroup.GET("/appPush", AppPushHandler)
	// 查询订单
	routeGroup.GET("/order/:orderId", getOrderGetHandler)
	routeGroup.Use(middleware.AuthMiddleware())
	// 重新回调订单
	routeGroup.PUT("/order/:orderId", reCallbackOrderHandler)
}

// extractGETParams 用于从GET请求中提取创建订单所需的参数
func extractGETParams(c *gin.Context) (*CreateOrderParams, error) {
    typeStr := c.Query("type")
    priceStr := c.Query("price")
    typeInt, err := strconv.Atoi(typeStr)
    if err != nil {
        return nil, fmt.Errorf("type error")
    }
    priceFloat, err := strconv.ParseFloat(priceStr, 64)
    if err != nil {
        return nil, fmt.Errorf("price error")
    }

    return &CreateOrderParams{
        PayId:     c.Query("payId"),
        Type:      typeInt,
        Price:     priceFloat,
        Sign:      c.Query("sign"),
        Param:     c.Query("param"),
        NotifyUrl: c.Query("notifyUrl"),
        ReturnUrl: c.Query("returnUrl"),
    }, nil
}

func qrcodeGetHandler(c *gin.Context) {
	content := c.Query("content")
	format := c.DefaultQuery("format", "json")
	if content == "" {
		c.JSON(200, gin.H{
			"code": -1,
			"msg":  "content is empty",
		})
		return
	}
	base64Str, err := qrcode.QrcodeFromStr(content)
	if err != nil {
		c.JSON(
			200,
			gin.H{
				"code": -1,
				"msg":  err.Error(),
			},
		)
		return
	}
	switch format {
	case "image":
		c.Writer.Header().Set("Content-Type", "image/png")
		c.Request.Header.Set("Content-Type", "image/png")
		// 将base64Str 转为 []byte
		buf, err := base64.StdEncoding.DecodeString(base64Str)
		if err != nil {
			c.JSON(
				200,
				gin.H{
					"code": -1,
					"msg":  err.Error(),
				},
			)
			return
		}
		c.Writer.Write(buf)
	default:
		c.JSON(200, gin.H{"qrcode": fmt.Sprintf("data:image/png;base64,%s", base64Str)})
	}
}

func qrcodePostHandler(c *gin.Context) {
	// 从请求中获取图片
	file, err := c.FormFile("file")
	if err != nil {
		c.Error(err)
		return
	}
	// 读取file 2 []byte
	src, err := file.Open()
	if err != nil {
		c.Error(err)
		return
	}
	defer src.Close()
	buf := make([]byte, file.Size)
	_, err = src.Read(buf)
	if err != nil {
		c.Set("code", http.StatusInternalServerError)
		c.Error(err)
		return
	}
	// []byte 2 base64
	base64Str := base64.StdEncoding.EncodeToString(buf)
	// 解读二维码
	content, err := qrcode.DecodeQrcodeFromStr(base64Str)
	if err != nil {
		c.Set("code", http.StatusInternalServerError)
		c.Error(err)
		return
	}
	c.Set("data", gin.H{"content": content})
}

type CreateOrderParams struct {
    PayId     string  `json:"payId" form:"payId"`
    Type      int     `json:"type" form:"type"`
    Price     float64 `json:"price" form:"price"`
    Sign      string  `json:"sign" form:"sign"`
    Param     string  `json:"param" form:"param"`
    NotifyUrl string  `json:"notifyUrl" form:"notifyUrl"`
    ReturnUrl string  `json:"returnUrl" form:"returnUrl"`
}

func creatOrderHandler(c *gin.Context) {
	// 检查订单是否过期
	task.CheckOrderExpire()
	// 检查心跳
	heart := task.CheckHeart()
	if !heart {
		c.JSON(200, gin.H{
			"code": -1,
			"msg":  "heart error",
		})
		return
	}
    // 初始化参数结构体
    var params CreateOrderParams

    // 尝试从POST表单获取参数
    payId := c.DefaultPostForm("payId", "")
    typeStr := c.DefaultPostForm("type", "")
    priceStr := c.DefaultPostForm("price", "")
    signStr := c.DefaultPostForm("sign", "")
    param := c.DefaultPostForm("param", "")
    notifyUrl := c.DefaultPostForm("notifyUrl", "")
    returnUrl := c.DefaultPostForm("returnUrl", "")

    // 如果POST表单中的关键参数为空，尝试从GET请求的Keys中获取
    if payId == "" || typeStr == "" || priceStr == "" || signStr == "" {
        payId, _ = c.Get("payId").(string)
        typeStr, _ = c.Get("type").(string)
        priceStr, _ = c.Get("price").(string)
        signStr, _ = c.Get("sign").(string)
        param, _ = c.Get("param").(string)
        notifyUrl, _ = c.Get("notifyUrl").(string)
        returnUrl, _ = c.Get("returnUrl").(string)
    }

    // 转换类型
    params.PayId = payId
    var err error
    params.Type, err = strconv.Atoi(typeStr)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"code": -1, "msg": "Type conversion error"})
        return
    }

    params.Price, err = strconv.ParseFloat(priceStr, 64)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"code": -1, "msg": "Price conversion error"})
        return
    }

    params.Sign = signStr
    params.Param = param
    params.NotifyUrl = notifyUrl
    params.ReturnUrl = returnUrl

    // 验证签名逻辑...
    appConfig, err := db.GetAppConfig()
    if err != nil {
        c.Error(err)
        return
    }
    computedSign := hash.GetMD5Hash(payId + param + typeStr + priceStr + appConfig.APISecret)
    if computedSign != params.Sign {
        c.JSON(http.StatusOK, gin.H{"code": -1, "msg": "Sign verification failed"})
        return
    }
	// 创建订单
	// 2. 验证订单是否存在
	_, err := db.GetPayOrderByPayID(params.PayId)
	if err == nil || err.Error() != "record not found" {
		c.JSON(200, gin.H{
			"code": -1,
			"msg":  "payId is exist",
		})
		return
	}
	err = nil
	// 3. 创建订单
	err = db.AddPayOrder(params.PayId, params.Type, params.Price, params.Param, params.NotifyUrl, params.ReturnUrl)
	if err != nil {
		c.JSON(200, gin.H{
			"code": -1,
			"msg":  err.Error(),
		})
		return
	}
	// 返回结果
	order, err := db.GetPayOrderByPayID(params.PayId)
	if err != nil {
		c.JSON(200, gin.H{
			"code": -1,
			"msg":  err.Error(),
		})
		return
	}
	timeout := (order.ExpectDate - order.CreateDate) / 1000 / 60 // 分钟
	c.IndentedJSON(200, gin.H{
		"code": 1,
		"msg":  "success",
		"data": gin.H{
			"payId":       order.PayID,
			"orderId":     order.OrderID,
			"payType":     order.Type,
			"price":       order.Price,
			"reallyPrice": order.ReallyPrice,
			"payUrl":      order.PayURL,
			"isAuto":      order.IsAuto,
			"state":       order.State,
			"createDate":  order.CreateDate,
			"expectDate":  order.ExpectDate,
			"timeOut":     timeout,
			"redirectUrl": fmt.Sprintf("/payment/%s", order.OrderID),
		},
	})
}

func getOrderGetHandler(c *gin.Context) {
	orderId := c.Param("orderId")
	if orderId == "" {
		c.Error(fmt.Errorf("orderId is empty"))
		return
	}
	order, err := db.GetPayOrderByOrderID(orderId)
	if err != nil {
		c.Error(err)
		return
	}
	c.Set("data", gin.H{
		"payId":       order.PayID,
		"orderId":     order.OrderID,
		"payType":     order.Type,
		"price":       order.Price,
		"reallyPrice": order.ReallyPrice,
		"payUrl":      order.PayURL,
		"isAuto":      order.IsAuto,
		"state":       order.State,
		"createDate":  order.CreateDate,
		"expectDate":  order.ExpectDate,
	})
}

func getOrderStateGetHandler(c *gin.Context) {
	orderId := c.Param("orderId")
	if orderId == "" {
		c.Error(fmt.Errorf("orderId is empty"))
		return
	}
	order, err := db.GetPayOrderByOrderID(orderId)
	if err != nil {
		if err.Error() == "record not found" {
			c.Error(fmt.Errorf("order not found"))
		} else {
			c.Error(err)
		}
		return
	}
	paramMap := map[string]string{
		"payId":       order.PayID,
		"param":       order.Param,
		"type":        fmt.Sprintf("%d", order.Type),
		"price":       utils.Float64ToSting(order.Price),
		"reallyPrice": utils.Float64ToSting(order.ReallyPrice),
	}
	appConfig, err := db.GetAppConfig()
	if err != nil {
		c.Error(err)
		return
	}
	// sign := hash.GetMD5Hash(payId + param + typeStr + priceStr + key.VValue)
	sign := hash.GetMD5Hash(fmt.Sprintf("%s%s%s%s%s", order.PayID, order.Param, fmt.Sprintf("%d", order.Type), utils.Float64ToSting(order.Price), utils.Float64ToSting(order.ReallyPrice)) + appConfig.APISecret)
	// 将map转为get参数 用于跳转
	paramStr := ""
	for k, v := range paramMap {
		paramStr += fmt.Sprintf("%s=%s&", k, v)
	}
	paramStr += fmt.Sprintf("sign=%s", sign)
	returnUrl := order.ReturnURL
	if returnUrl == "" {
		returnUrl = appConfig.ReturnUrl
	}
	var state int
	if order.State >= 1 {
		state = 1
		returnUrl = fmt.Sprintf("%s?%s", returnUrl, paramStr)
	} else {
		state = order.State
		returnUrl = ""
	}
	c.Set("data", gin.H{
		"state":     state,
		"returnUrl": returnUrl,
	})
}

func reCallbackOrderHandler(c *gin.Context) {
	orderId := c.Param("orderId")
	if orderId == "" {
		c.Error(fmt.Errorf("orderId is empty"))
		return
	}
	order, err := db.GetPayOrderByOrderID(orderId)
	if err != nil {
		c.Error(err)
		return
	}
	if order.State != 1 {
		c.Error(fmt.Errorf("order state error"))
		return
	}
	task.Notify(order)
	c.Set("code", http.StatusOK)
}

func captchaHandler(c *gin.Context) {
	id, b64s, err := captcha.GenerateCaptcha()
	if err != nil {
		c.Error(err)
		return
	}
	c.Set("data", gin.H{
		"id":      id,
		"captcha": b64s,
	})
}

func HeartHandler(c *gin.Context) {
	time := c.Query("t")
	if time == "" {
		c.Error(fmt.Errorf("t is empty"))
		return
	}
	timeInt, err := strconv.ParseInt(time, 10, 64)
	if err != nil {
		c.Error(fmt.Errorf("time error"))
		return
	}
	timeNow := utils.GetUnix13()
	// 如果时间差大于10秒
	if math.Abs(float64(timeNow-timeInt)) > 10000 {
		c.Error(fmt.Errorf("time error"))
		return
	}
	sign := c.Query("sign")
	if sign == "" {
		c.Error(fmt.Errorf("sign is empty"))
		return
	}
	appConfig, err := db.GetAppConfig()
	if err != nil {
		c.Error(err)
		return
	}
	if hash.GetMD5Hash(time+appConfig.APISecret) != sign {
		c.Error(fmt.Errorf("sign error"))
		return
	}
	err = db.UpdateSetting("lastHeart", time)
	if err != nil {
		c.Error(err)
		return
	}
	c.Set("code", http.StatusOK)
	c.Set("data", "success")
}

func AppPushHandler(c *gin.Context) {
	t := c.Query("t")
	if t == "" {
		c.Error(fmt.Errorf("t is empty"))
		return
	}
	_type := c.Query("type") // 1:微信 2:支付宝
	if _type == "" {
		c.Error(fmt.Errorf("type is empty"))
		return
	}
	if _type != "1" && _type != "2" {
		c.Error(fmt.Errorf("type error"))
		return
	}
	typeInt, err := strconv.Atoi(_type)
	if err != nil {
		c.Error(err)
		return
	}
	price := c.Query("price")
	priceFloat, err := strconv.ParseFloat(price, 64)
	if err != nil {
		c.Error(err)
		return
	}
	sign := c.Query("sign")
	if sign == "" {
		c.Error(fmt.Errorf("sign is empty"))
		return
	}
	metdata := c.DefaultQuery("metadata", "")
	appConfig, err := db.GetAppConfig()
	if err != nil {
		c.Error(err)
		return
	}
	if hash.GetMD5Hash(_type+price+t+appConfig.APISecret) != sign {
		c.Error(fmt.Errorf("sign error"))
		return
	}
	go task.AppPush(typeInt, priceFloat, metdata)
	c.Set("code", http.StatusOK)
}
