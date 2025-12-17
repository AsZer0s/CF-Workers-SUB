
// 部署完成后在网址后面加上这个，获取自建节点和机场聚合节点，/?token=auto或/auto或

let mytoken = 'auto';
let guestToken = ''; //可以随便取，或者uuid生成，https://1024tools.com/uuid
let BotToken = ''; //可以为空，或者@BotFather中输入/start，/newbot，并关注机器人
let ChatID = ''; //可以为空，或者@userinfobot中获取，/start
let TG = 0; //小白勿动， 开发者专用，1 为推送所有的访问信息，0 为不推送订阅转换后端的访问信息与异常访问
let FileName = 'CF-Workers-SUB';
let SUBUpdateTime = 6; //自定义订阅更新时间，单位小时
let total = 99;//TB
let timestamp = 4102329600000;//2099-12-31

//节点链接 + 订阅链接
let MainData = `
https://cfxr.eu.org/getSub
`;

let urls = [];
let subConverter = "SUBAPI.cmliussss.net"; //在线订阅转换后端，目前使用CM的订阅转换功能。支持自建psub 可自行搭建https://github.com/bulianglin/psub
let subConfig = "https://raw.githubusercontent.com/cmliu/ACL4SSR/main/Clash/config/ACL4SSR_Online_MultiCountry.ini"; //订阅配置文件
let subProtocol = 'https';

export default {
	async fetch(request, env) {
		const userAgentHeader = request.headers.get('User-Agent');
		const userAgent = userAgentHeader ? userAgentHeader.toLowerCase() : "null";
		const url = new URL(request.url);
		let token = url.searchParams.get('token');
		mytoken = env.TOKEN || mytoken;
		BotToken = env.TGTOKEN || BotToken;
		ChatID = env.TGID || ChatID;
		TG = env.TG || TG;
		subConverter = env.SUBAPI || subConverter;
		if (subConverter.includes("http://")) {
			subConverter = subConverter.split("//")[1];
			subProtocol = 'http';
		} else {
			subConverter = subConverter.split("//")[1] || subConverter;
		}
		subConfig = env.SUBCONFIG || subConfig;
		FileName = env.SUBNAME || FileName;

		const currentDate = new Date();
		currentDate.setHours(0, 0, 0, 0);
		const timeTemp = Math.ceil(currentDate.getTime() / 1000);
		const fakeToken = await MD5MD5(`${mytoken}${timeTemp}`);
		guestToken = env.GUESTTOKEN || env.GUEST || guestToken;
		if (!guestToken) guestToken = await MD5MD5(mytoken);
		const 访客订阅 = guestToken;
		//console.log(`${fakeUserID}\n${fakeHostName}`); // 打印fakeID

		let UD = Math.floor(((timestamp - Date.now()) / timestamp * total * 1099511627776) / 2);
		total = total * 1099511627776;
		let expire = Math.floor(timestamp / 1000);
		SUBUpdateTime = env.SUBUPTIME || SUBUpdateTime;

		// 从KV获取所有token列表（多订阅支持）
		let validTokens = [mytoken, fakeToken, 访客订阅];
		if (env.KV) {
			const tokenList = await env.KV.get('TOKEN_LIST');
			if (tokenList) {
				const tokens = tokenList.split('\n').filter(t => t.trim());
				validTokens = [...validTokens, ...tokens];
			}
		}

		// 从pathname提取token（支持 /token 格式）
		let pathToken = null;
		if (url.pathname && url.pathname.length > 1) {
			pathToken = url.pathname.substring(1).split('?')[0];
			// 如果pathToken在有效token列表中，使用它作为token
			if (validTokens.includes(pathToken)) {
				token = pathToken;
			}
		}

		// 检查是否为有效token（包括pathname匹配）
		const isValidToken = validTokens.includes(token) || 
			validTokens.includes(pathToken) || 
			url.pathname == ("/" + mytoken) || 
			url.pathname.includes("/" + mytoken + "?");
		
		if (!isValidToken) {
			if (TG == 1 && url.pathname !== "/" && url.pathname !== "/favicon.ico") await sendMessage(`#异常访问 ${FileName}`, request.headers.get('CF-Connecting-IP'), `UA: ${userAgent}</tg-spoiler>\n域名: ${url.hostname}\n<tg-spoiler>入口: ${url.pathname + url.search}</tg-spoiler>`);
			if (env.URL302) return Response.redirect(env.URL302, 302);
			else if (env.URL) return await proxyURL(env.URL, url);
			else return new Response(await nginx(), {
				status: 200,
				headers: {
					'Content-Type': 'text/html; charset=UTF-8',
				},
			});
		} else {
			// 确定当前使用的token（fakeToken视为mytoken）
			let currentToken = token || pathToken || mytoken;
			if (currentToken === fakeToken) {
				currentToken = mytoken; // fakeToken使用主token的数据
			}
			const isMainToken = currentToken === mytoken;
			
			if (env.KV) {
				// 优先处理POST请求的action（创建/删除/保存）
				if (isMainToken && request.method === 'POST' && url.searchParams.has('action')) {
					const action = url.searchParams.get('action');
					console.log(`收到POST请求 - Action: ${action}, URL: ${url.href}`);
					if (action === 'create') {
						const newToken = await request.text();
						console.log(`创建订阅请求 - Token: ${newToken.trim()}`);
						return await createSubscription(env, newToken.trim(), mytoken, fakeToken, 访客订阅);
					} else if (action === 'delete') {
						const delToken = await request.text();
						console.log(`删除订阅请求 - Token: ${delToken.trim()}`);
						return await deleteSubscription(env, delToken.trim());
					} else if (action === 'saveLink') {
						const token = url.searchParams.get('token');
						const linkContent = await request.text();
						if (token) {
							console.log(`保存LINK - Token: ${token}, ContentLength: ${linkContent.length}`);
							await env.KV.put(`LINK_${token}.txt`, linkContent);
							// 验证保存是否成功
							const verify = await env.KV.get(`LINK_${token}.txt`);
							if (verify === null) {
								console.error(`LINK保存验证失败 - Token: ${token}`);
								return new Response("LINK保存失败: 验证失败", { status: 500 });
							}
							console.log(`LINK保存成功 - Token: ${token}, VerifiedLength: ${verify.length}`);
							return new Response("LINK保存成功");
						}
						return new Response("Token不能为空", { status: 400 });
					}
				}
				
				// 处理管理界面的GET请求
				if (isMainToken && userAgent.includes('mozilla') && url.searchParams.has('manage') && request.method === 'GET') {
					return await manageSubscriptions(request, env, mytoken, url);
				}
				
				// WebUI界面（浏览器访问）- 只有主token显示WebUI编辑界面
				if (isMainToken && userAgent.includes('mozilla') && !url.searchParams.has('sub')) {
					await sendMessage(`#编辑订阅 ${FileName}`, request.headers.get('CF-Connecting-IP'), `UA: ${userAgentHeader}</tg-spoiler>\n域名: ${url.hostname}\n<tg-spoiler>入口: ${url.pathname + url.search}</tg-spoiler>`);
					// 主token显示编辑界面
					return await KV(request, env, 'LINK.txt', 访客订阅, mytoken, true, mytoken, FileName, subProtocol, subConverter, subConfig);
				}
				
				// 其他token（管理界面创建的）浏览器访问时，直接返回订阅内容，不显示WebUI
				if (!isMainToken && userAgent.includes('mozilla') && !url.searchParams.has('sub')) {
					// 直接继续执行订阅生成逻辑，不返回WebUI
				}
				
				// 获取订阅数据（根据token从对应的KV key读取）
				const kvKey = isMainToken ? 'LINK.txt' : `LINK_${currentToken}.txt`;
				await 迁移地址列表(env, kvKey);
				MainData = await env.KV.get(kvKey) || MainData;
			} else {
				MainData = env.LINK || MainData;
				if (env.LINKSUB) urls = await ADD(env.LINKSUB);
			}
			let 重新汇总所有链接 = await ADD(MainData + '\n' + urls.join('\n'));
			let 自建节点 = "";
			let 订阅链接 = "";
			for (let x of 重新汇总所有链接) {
				if (x.toLowerCase().startsWith('http')) {
					订阅链接 += x + '\n';
				} else {
					自建节点 += x + '\n';
				}
			}
			MainData = 自建节点;
			urls = await ADD(订阅链接);
			await sendMessage(`#获取订阅 ${FileName}`, request.headers.get('CF-Connecting-IP'), `UA: ${userAgentHeader}</tg-spoiler>\n域名: ${url.hostname}\n<tg-spoiler>入口: ${url.pathname + url.search}</tg-spoiler>`);
			const isSubConverterRequest = request.headers.get('subconverter-request') || request.headers.get('subconverter-version') || userAgent.includes('subconverter');
			let 订阅格式 = 'base64';
			if (!(userAgent.includes('null') || isSubConverterRequest || userAgent.includes('nekobox') || userAgent.includes(('CF-Workers-SUB').toLowerCase()))) {
				if (userAgent.includes('sing-box') || userAgent.includes('singbox') || url.searchParams.has('sb') || url.searchParams.has('singbox')) {
					订阅格式 = 'singbox';
				} else if (userAgent.includes('surge') || url.searchParams.has('surge')) {
					订阅格式 = 'surge';
				} else if (userAgent.includes('quantumult') || url.searchParams.has('quanx')) {
					订阅格式 = 'quanx';
				} else if (userAgent.includes('loon') || url.searchParams.has('loon')) {
					订阅格式 = 'loon';
				} else if (userAgent.includes('clash') || userAgent.includes('meta') || userAgent.includes('mihomo') || url.searchParams.has('clash')) {
					订阅格式 = 'clash';
				}
			}

			let subConverterUrl;
			// 使用当前token生成订阅转换URL（fakeToken视为mytoken）
			const urlToken = (token === fakeToken) ? mytoken : (token || pathToken || mytoken);
			let 订阅转换URL = `${url.origin}/${urlToken}?token=${urlToken}`;
			//console.log(订阅转换URL);
			let req_data = MainData;

			let 追加UA = 'v2rayn';
			if (url.searchParams.has('b64') || url.searchParams.has('base64')) 订阅格式 = 'base64';
			else if (url.searchParams.has('clash')) 追加UA = 'clash';
			else if (url.searchParams.has('singbox')) 追加UA = 'singbox';
			else if (url.searchParams.has('surge')) 追加UA = 'surge';
			else if (url.searchParams.has('quanx')) 追加UA = 'Quantumult%20X';
			else if (url.searchParams.has('loon')) 追加UA = 'Loon';

			const 订阅链接数组 = [...new Set(urls)].filter(item => item?.trim?.()); // 去重
			if (订阅链接数组.length > 0) {
				const 请求订阅响应内容 = await getSUB(订阅链接数组, request, 追加UA, userAgentHeader);
				console.log(请求订阅响应内容);
				req_data += 请求订阅响应内容[0].join('\n');
				订阅转换URL += "|" + 请求订阅响应内容[1];
				if (订阅格式 == 'base64' && !isSubConverterRequest && 请求订阅响应内容[1].includes('://')) {
					subConverterUrl = `${subProtocol}://${subConverter}/sub?target=mixed&url=${encodeURIComponent(请求订阅响应内容[1])}&insert=false&config=${encodeURIComponent(subConfig)}&emoji=true&list=false&tfo=false&scv=true&fdn=false&sort=false&new_name=true`;
					try {
						const subConverterResponse = await fetch(subConverterUrl, { headers: { 'User-Agent': 'v2rayN/CF-Workers-SUB  (https://github.com/cmliu/CF-Workers-SUB)' } });
						if (subConverterResponse.ok) {
							const subConverterContent = await subConverterResponse.text();
							req_data += '\n' + atob(subConverterContent);
						}
					} catch (error) {
						console.log('订阅转换请回base64失败，检查订阅转换后端是否正常运行');
					}
				}
			}

			if (env.WARP) 订阅转换URL += "|" + (await ADD(env.WARP)).join("|");
			//修复中文错误
			const utf8Encoder = new TextEncoder();
			const encodedData = utf8Encoder.encode(req_data);
			//const text = String.fromCharCode.apply(null, encodedData);
			const utf8Decoder = new TextDecoder();
			const text = utf8Decoder.decode(encodedData);

			//去重
			const uniqueLines = new Set(text.split('\n'));
			const result = [...uniqueLines].join('\n');
			//console.log(result);

			let base64Data;
			try {
				base64Data = btoa(result);
			} catch (e) {
				function encodeBase64(data) {
					const binary = new TextEncoder().encode(data);
					let base64 = '';
					const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

					for (let i = 0; i < binary.length; i += 3) {
						const byte1 = binary[i];
						const byte2 = binary[i + 1] || 0;
						const byte3 = binary[i + 2] || 0;

						base64 += chars[byte1 >> 2];
						base64 += chars[((byte1 & 3) << 4) | (byte2 >> 4)];
						base64 += chars[((byte2 & 15) << 2) | (byte3 >> 6)];
						base64 += chars[byte3 & 63];
					}

					const padding = 3 - (binary.length % 3 || 3);
					return base64.slice(0, base64.length - padding) + '=='.slice(0, padding);
				}

				base64Data = encodeBase64(result)
			}

			// 构建响应头对象
			const responseHeaders = {
				"content-type": "text/plain; charset=utf-8",
				"Profile-Update-Interval": `${SUBUpdateTime}`,
				"Profile-web-page-url": request.url.includes('?') ? request.url.split('?')[0] : request.url,
				//"Subscription-Userinfo": `upload=${UD}; download=${UD}; total=${total}; expire=${expire}`,
			};

			if (订阅格式 == 'base64' || token == fakeToken) {
				return new Response(base64Data, { headers: responseHeaders });
			} else if (订阅格式 == 'clash') {
				subConverterUrl = `${subProtocol}://${subConverter}/sub?target=clash&url=${encodeURIComponent(订阅转换URL)}&insert=false&config=${encodeURIComponent(subConfig)}&emoji=true&list=false&tfo=false&scv=true&fdn=false&sort=false&new_name=true`;
			} else if (订阅格式 == 'singbox') {
				subConverterUrl = `${subProtocol}://${subConverter}/sub?target=singbox&url=${encodeURIComponent(订阅转换URL)}&insert=false&config=${encodeURIComponent(subConfig)}&emoji=true&list=false&tfo=false&scv=true&fdn=false&sort=false&new_name=true`;
			} else if (订阅格式 == 'surge') {
				subConverterUrl = `${subProtocol}://${subConverter}/sub?target=surge&ver=4&url=${encodeURIComponent(订阅转换URL)}&insert=false&config=${encodeURIComponent(subConfig)}&emoji=true&list=false&tfo=false&scv=true&fdn=false&sort=false&new_name=true`;
			} else if (订阅格式 == 'quanx') {
				subConverterUrl = `${subProtocol}://${subConverter}/sub?target=quanx&url=${encodeURIComponent(订阅转换URL)}&insert=false&config=${encodeURIComponent(subConfig)}&emoji=true&list=false&tfo=false&scv=true&fdn=false&sort=false&udp=true`;
			} else if (订阅格式 == 'loon') {
				subConverterUrl = `${subProtocol}://${subConverter}/sub?target=loon&url=${encodeURIComponent(订阅转换URL)}&insert=false&config=${encodeURIComponent(subConfig)}&emoji=true&list=false&tfo=false&scv=true&fdn=false&sort=false`;
			}
			//console.log(订阅转换URL);
			try {
				const subConverterResponse = await fetch(subConverterUrl, { headers: { 'User-Agent': userAgentHeader } });//订阅转换
				if (!subConverterResponse.ok) return new Response(base64Data, { headers: responseHeaders });
				let subConverterContent = await subConverterResponse.text();
				if (订阅格式 == 'clash') subConverterContent = await clashFix(subConverterContent);
				// 只有非浏览器订阅才会返回SUBNAME
				if (!userAgent.includes('mozilla')) responseHeaders["Content-Disposition"] = `attachment; filename*=utf-8''${encodeURIComponent(FileName)}`;
				return new Response(subConverterContent, { headers: responseHeaders });
			} catch (error) {
				return new Response(base64Data, { headers: responseHeaders });
			}
		}
	}
};

async function ADD(envadd) {
	var addtext = envadd.replace(/[	"'|\r\n]+/g, '\n').replace(/\n+/g, '\n');	// 替换为换行
	//console.log(addtext);
	if (addtext.charAt(0) == '\n') addtext = addtext.slice(1);
	if (addtext.charAt(addtext.length - 1) == '\n') addtext = addtext.slice(0, addtext.length - 1);
	const add = addtext.split('\n');
	//console.log(add);
	return add;
}

async function nginx() {
	const text = `
	<!DOCTYPE html>
	<html>
	<head>
	<title>Welcome to nginx!</title>
	<style>
		body {
			width: 35em;
			margin: 0 auto;
			font-family: Tahoma, Verdana, Arial, sans-serif;
		}
	</style>
	</head>
	<body>
	<h1>Welcome to nginx!</h1>
	<p>If you see this page, the nginx web server is successfully installed and
	working. Further configuration is required.</p>
	
	<p>For online documentation and support please refer to
	<a href="http://nginx.org/">nginx.org</a>.<br/>
	Commercial support is available at
	<a href="http://nginx.com/">nginx.com</a>.</p>
	
	<p><em>Thank you for using nginx.</em></p>
	</body>
	</html>
	`
	return text;
}

async function sendMessage(type, ip, add_data = "") {
	if (BotToken !== '' && ChatID !== '') {
		let msg = "";
		const response = await fetch(`http://ip-api.com/json/${ip}?lang=zh-CN`);
		if (response.status == 200) {
			const ipInfo = await response.json();
			msg = `${type}\nIP: ${ip}\n国家: ${ipInfo.country}\n<tg-spoiler>城市: ${ipInfo.city}\n组织: ${ipInfo.org}\nASN: ${ipInfo.as}\n${add_data}`;
		} else {
			msg = `${type}\nIP: ${ip}\n<tg-spoiler>${add_data}`;
		}

		let url = "https://api.telegram.org/bot" + BotToken + "/sendMessage?chat_id=" + ChatID + "&parse_mode=HTML&text=" + encodeURIComponent(msg);
		return fetch(url, {
			method: 'get',
			headers: {
				'Accept': 'text/html,application/xhtml+xml,application/xml;',
				'Accept-Encoding': 'gzip, deflate, br',
				'User-Agent': 'Mozilla/5.0 Chrome/90.0.4430.72'
			}
		});
	}
}

function base64Decode(str) {
	const bytes = new Uint8Array(atob(str).split('').map(c => c.charCodeAt(0)));
	const decoder = new TextDecoder('utf-8');
	return decoder.decode(bytes);
}

async function MD5MD5(text) {
	const encoder = new TextEncoder();

	const firstPass = await crypto.subtle.digest('MD5', encoder.encode(text));
	const firstPassArray = Array.from(new Uint8Array(firstPass));
	const firstHex = firstPassArray.map(b => b.toString(16).padStart(2, '0')).join('');

	const secondPass = await crypto.subtle.digest('MD5', encoder.encode(firstHex.slice(7, 27)));
	const secondPassArray = Array.from(new Uint8Array(secondPass));
	const secondHex = secondPassArray.map(b => b.toString(16).padStart(2, '0')).join('');

	return secondHex.toLowerCase();
}

function clashFix(content) {
	if (content.includes('wireguard') && !content.includes('remote-dns-resolve')) {
		let lines;
		if (content.includes('\r\n')) {
			lines = content.split('\r\n');
		} else {
			lines = content.split('\n');
		}

		let result = "";
		for (let line of lines) {
			if (line.includes('type: wireguard')) {
				const 备改内容 = `, mtu: 1280, udp: true`;
				const 正确内容 = `, mtu: 1280, remote-dns-resolve: true, udp: true`;
				result += line.replace(new RegExp(备改内容, 'g'), 正确内容) + '\n';
			} else {
				result += line + '\n';
			}
		}

		content = result;
	}
	return content;
}

async function proxyURL(proxyURL, url) {
	const URLs = await ADD(proxyURL);
	const fullURL = URLs[Math.floor(Math.random() * URLs.length)];

	// 解析目标 URL
	let parsedURL = new URL(fullURL);
	console.log(parsedURL);
	// 提取并可能修改 URL 组件
	let URLProtocol = parsedURL.protocol.slice(0, -1) || 'https';
	let URLHostname = parsedURL.hostname;
	let URLPathname = parsedURL.pathname;
	let URLSearch = parsedURL.search;

	// 处理 pathname
	if (URLPathname.charAt(URLPathname.length - 1) == '/') {
		URLPathname = URLPathname.slice(0, -1);
	}
	URLPathname += url.pathname;

	// 构建新的 URL
	let newURL = `${URLProtocol}://${URLHostname}${URLPathname}${URLSearch}`;

	// 反向代理请求
	let response = await fetch(newURL);

	// 创建新的响应
	let newResponse = new Response(response.body, {
		status: response.status,
		statusText: response.statusText,
		headers: response.headers
	});

	// 添加自定义头部，包含 URL 信息
	//newResponse.headers.set('X-Proxied-By', 'Cloudflare Worker');
	//newResponse.headers.set('X-Original-URL', fullURL);
	newResponse.headers.set('X-New-URL', newURL);

	return newResponse;
}

async function getSUB(api, request, 追加UA, userAgentHeader) {
	if (!api || api.length === 0) {
		return [];
	} else api = [...new Set(api)]; // 去重
	let newapi = "";
	let 订阅转换URLs = "";
	let 异常订阅 = "";
	const controller = new AbortController(); // 创建一个AbortController实例，用于取消请求
	const timeout = setTimeout(() => {
		controller.abort(); // 2秒后取消所有请求
	}, 2000);

	try {
		// 使用Promise.allSettled等待所有API请求完成，无论成功或失败
		const responses = await Promise.allSettled(api.map(apiUrl => getUrl(request, apiUrl, 追加UA, userAgentHeader).then(response => response.ok ? response.text() : Promise.reject(response))));

		// 遍历所有响应
		const modifiedResponses = responses.map((response, index) => {
			// 检查是否请求成功
			if (response.status === 'rejected') {
				const reason = response.reason;
				if (reason && reason.name === 'AbortError') {
					return {
						status: '超时',
						value: null,
						apiUrl: api[index] // 将原始的apiUrl添加到返回对象中
					};
				}
				console.error(`请求失败: ${api[index]}, 错误信息: ${reason.status} ${reason.statusText}`);
				return {
					status: '请求失败',
					value: null,
					apiUrl: api[index] // 将原始的apiUrl添加到返回对象中
				};
			}
			return {
				status: response.status,
				value: response.value,
				apiUrl: api[index] // 将原始的apiUrl添加到返回对象中
			};
		});

		console.log(modifiedResponses); // 输出修改后的响应数组

		for (const response of modifiedResponses) {
			// 检查响应状态是否为'fulfilled'
			if (response.status === 'fulfilled') {
				const content = await response.value || 'null'; // 获取响应的内容
				if (content.includes('proxies:')) {
					//console.log('Clash订阅: ' + response.apiUrl);
					订阅转换URLs += "|" + response.apiUrl; // Clash 配置
				} else if (content.includes('outbounds"') && content.includes('inbounds"')) {
					//console.log('Singbox订阅: ' + response.apiUrl);
					订阅转换URLs += "|" + response.apiUrl; // Singbox 配置
				} else if (content.includes('://')) {
					//console.log('明文订阅: ' + response.apiUrl);
					newapi += content + '\n'; // 追加内容
				} else if (isValidBase64(content)) {
					//console.log('Base64订阅: ' + response.apiUrl);
					newapi += base64Decode(content) + '\n'; // 解码并追加内容
				} else {
					const 异常订阅LINK = `trojan://CMLiussss@127.0.0.1:8888?security=tls&allowInsecure=1&type=tcp&headerType=none#%E5%BC%82%E5%B8%B8%E8%AE%A2%E9%98%85%20${response.apiUrl.split('://')[1].split('/')[0]}`;
					console.log('异常订阅: ' + 异常订阅LINK);
					异常订阅 += `${异常订阅LINK}\n`;
				}
			}
		}
	} catch (error) {
		console.error(error); // 捕获并输出错误信息
	} finally {
		clearTimeout(timeout); // 清除定时器
	}

	const 订阅内容 = await ADD(newapi + 异常订阅); // 将处理后的内容转换为数组
	// 返回处理后的结果
	return [订阅内容, 订阅转换URLs];
}

async function getUrl(request, targetUrl, 追加UA, userAgentHeader) {
	// 设置自定义 User-Agent
	const newHeaders = new Headers(request.headers);
	newHeaders.set("User-Agent", `${atob('djJyYXlOLzYuNDU=')} cmliu/CF-Workers-SUB ${追加UA}(${userAgentHeader})`);

	// 构建新的请求对象
	const modifiedRequest = new Request(targetUrl, {
		method: request.method,
		headers: newHeaders,
		body: request.method === "GET" ? null : request.body,
		redirect: "follow",
		cf: {
			// 忽略SSL证书验证
			insecureSkipVerify: true,
			// 允许自签名证书
			allowUntrusted: true,
			// 禁用证书验证
			validateCertificate: false
		}
	});

	// 输出请求的详细信息
	console.log(`请求URL: ${targetUrl}`);
	console.log(`请求头: ${JSON.stringify([...newHeaders])}`);
	console.log(`请求方法: ${request.method}`);
	console.log(`请求体: ${request.method === "GET" ? null : request.body}`);

	// 发送请求并返回响应
	return fetch(modifiedRequest);
}

function isValidBase64(str) {
	// 先移除所有空白字符(空格、换行、回车等)
	const cleanStr = str.replace(/\s/g, '');
	const base64Regex = /^[A-Za-z0-9+/=]+$/;
	return base64Regex.test(cleanStr);
}

async function 迁移地址列表(env, txt = 'ADD.txt') {
	const 旧数据 = await env.KV.get(`/${txt}`);
	const 新数据 = await env.KV.get(txt);

	if (旧数据 && !新数据) {
		// 写入新位置
		await env.KV.put(txt, 旧数据);
		// 删除旧数据
		await env.KV.delete(`/${txt}`);
		return true;
	}
	return false;
}

// 创建订阅
async function createSubscription(env, newToken, mytoken = 'auto', fakeToken = '', guestToken = '') {
	console.log('=== 开始创建订阅 ===');
	console.log('newToken:', newToken);
	
	if (!env.KV) {
		console.error('KV未绑定');
		return new Response("未绑定KV空间", { status: 400 });
	}
	if (!newToken || newToken.trim() === '') {
		console.error('Token为空');
		return new Response("Token不能为空", { status: 400 });
	}
	
	const trimmedToken = newToken.trim();
	console.log('trimmedToken:', trimmedToken);
	
	// 检查是否与系统保留token冲突
	const reservedTokens = [mytoken, fakeToken, guestToken].filter(t => t && t.trim());
	if (reservedTokens.includes(trimmedToken)) {
		console.error(`Token与系统保留token冲突: ${trimmedToken}`);
		return new Response(`Token不能使用保留关键字，请使用其他名称`, { status: 400 });
	}
	
	// 检查是否包含特殊字符或路径分隔符
	if (trimmedToken.includes('/') || trimmedToken.includes('?') || trimmedToken.includes('&') || trimmedToken.includes('#')) {
		console.error(`Token包含非法字符: ${trimmedToken}`);
		return new Response("Token不能包含特殊字符（/、?、&、#）", { status: 400 });
	}
	
	try {
		// 获取现有token列表
		const tokenList = await env.KV.get('TOKEN_LIST') || '';
		console.log('当前TOKEN_LIST:', tokenList);
		const tokens = tokenList.split('\n').filter(t => t.trim());
		console.log('解析后的tokens:', tokens);
		
		// 检查token是否已存在
		if (tokens.includes(trimmedToken)) {
			return new Response("Token已存在", { status: 400 });
		}
		
		// 再次检查是否与保留token冲突（防止动态token如fakeToken）
		if (reservedTokens.includes(trimmedToken)) {
			console.error(`Token与系统保留token冲突: ${trimmedToken}`);
			return new Response(`Token不能使用保留关键字，请使用其他名称`, { status: 400 });
		}
		
		// 添加新token
		tokens.push(trimmedToken);
		const newTokenList = tokens.join('\n');
		
		// 写入TOKEN_LIST
		console.log(`准备写入TOKEN_LIST: ${newTokenList}`);
		await env.KV.put('TOKEN_LIST', newTokenList);
		
		// 验证TOKEN_LIST是否写入成功（可能需要等待KV最终一致性）
		let verifyTokenList = await env.KV.get('TOKEN_LIST');
		let retryCount = 0;
		while ((!verifyTokenList || !verifyTokenList.includes(trimmedToken)) && retryCount < 3) {
			console.log(`TOKEN_LIST验证重试 ${retryCount + 1}/3`);
			await new Promise(resolve => setTimeout(resolve, 100)); // 等待100ms
			verifyTokenList = await env.KV.get('TOKEN_LIST');
			retryCount++;
		}
		
		if (!verifyTokenList || !verifyTokenList.includes(trimmedToken)) {
			console.error(`TOKEN_LIST写入验证失败 - Expected: ${trimmedToken}, Got: ${verifyTokenList}`);
			return new Response("创建失败: TOKEN_LIST写入失败", { status: 500 });
		}
		
		console.log(`TOKEN_LIST写入成功: ${verifyTokenList}`);
		
		// 创建空的订阅数据
		const linkKey = `LINK_${trimmedToken}.txt`;
		console.log(`准备写入LINK文件: ${linkKey}`);
		await env.KV.put(linkKey, '');
		
		// 验证LINK文件是否写入成功
		let verifyLink = await env.KV.get(linkKey);
		retryCount = 0;
		while (verifyLink === null && retryCount < 3) {
			console.log(`LINK文件验证重试 ${retryCount + 1}/3`);
			await new Promise(resolve => setTimeout(resolve, 100)); // 等待100ms
			verifyLink = await env.KV.get(linkKey);
			retryCount++;
		}
		
		if (verifyLink === null) {
			console.error(`LINK文件写入验证失败 - Key: ${linkKey}`);
			return new Response("创建失败: LINK文件写入失败", { status: 500 });
		}
		
		console.log(`订阅创建成功: ${trimmedToken}, LINK文件: ${linkKey}`);
		return new Response("订阅创建成功");
	} catch (error) {
		console.error('创建订阅时发生错误:', error);
		return new Response("创建失败: " + error.message, { status: 500 });
	}
}

// 删除订阅
async function deleteSubscription(env, delToken) {
	if (!env.KV) return new Response("未绑定KV空间", { status: 400 });
	if (!delToken || delToken.trim() === '') {
		return new Response("Token不能为空", { status: 400 });
	}
	
	try {
		// 获取现有token列表
		const tokenList = await env.KV.get('TOKEN_LIST') || '';
		const tokens = tokenList.split('\n').filter(t => t.trim());
		
		// 移除token
		const newTokens = tokens.filter(t => t !== delToken.trim());
		await env.KV.put('TOKEN_LIST', newTokens.join('\n'));
		
		// 删除订阅数据
		await env.KV.delete(`LINK_${delToken.trim()}.txt`);
		
		return new Response("订阅删除成功");
	} catch (error) {
		console.error('删除订阅时发生错误:', error);
		return new Response("删除失败: " + error.message, { status: 500 });
	}
}

// 管理订阅界面
async function manageSubscriptions(request, env, mytoken, url) {
	if (!env.KV) {
		return new Response("未绑定KV空间", { status: 400 });
	}
	
	try {
		const tokenList = await env.KV.get('TOKEN_LIST') || '';
		const tokens = tokenList.split('\n').filter(t => t.trim());
		
		console.log('管理界面 - TOKEN_LIST:', tokenList);
		console.log('管理界面 - 解析后的tokens:', tokens);
		
		let subscriptionsHtml = '';
		if (tokens.length > 0) {
			// 获取每个token的LINK内容
			const tokenLinks = await Promise.all(tokens.map(async token => {
				const linkKey = `LINK_${token}.txt`;
				const linkContent = await env.KV.get(linkKey) || '';
				console.log(`管理界面 - Token: ${token}, LinkKey: ${linkKey}, ContentLength: ${linkContent.length}`);
				return { token, linkContent };
			}));
			
			subscriptionsHtml = tokenLinks.map(({ token, linkContent }) => {
				const hasLink = linkContent.trim().length > 0;
				// HTML转义，防止XSS和模板字符串问题
				const escapedLinkContent = linkContent
					.replace(/&/g, '&amp;')
					.replace(/</g, '&lt;')
					.replace(/>/g, '&gt;')
					.replace(/"/g, '&quot;')
					.replace(/'/g, '&#39;');
				return `
					<div style="border: 1px solid #ccc; padding: 15px; margin: 10px 0; border-radius: 4px; background: #f9f9f9;">
						<strong>Token: ${token}</strong><br><br>
						<div id="linkInput_${token}" style="${hasLink ? 'display: none;' : ''}">
							<label style="display: block; margin-bottom: 5px; font-weight: bold;">输入LINK（节点链接或订阅链接，每行一个）:</label>
							<textarea id="linkContent_${token}" rows="5" style="width: 100%; padding: 8px; border: 1px solid #ccc; border-radius: 4px; font-size: 13px; box-sizing: border-box;" placeholder="vless://...&#10;vmess://...&#10;https://sub.example.com">${escapedLinkContent}</textarea>
							<button onclick="saveLink('${token}')" style="background: #4CAF50; color: white; border: none; padding: 6px 15px; border-radius: 4px; cursor: pointer; margin-top: 5px;">保存LINK</button>
							<span id="saveStatus_${token}" style="margin-left: 10px;"></span>
						</div>
						<div id="linkDisplay_${token}" style="${hasLink ? '' : 'display: none;'}">
							<strong>订阅链接:</strong><br>
							<div style="background: #fff; padding: 10px; margin: 5px 0; border-radius: 4px; border: 1px solid #ddd;">
								自适应: <a href="https://${url.hostname}/${token}" target="_blank" style="color: #1976D2;">https://${url.hostname}/${token}</a><br>
								Base64: <a href="https://${url.hostname}/${token}?b64" target="_blank" style="color: #1976D2;">https://${url.hostname}/${token}?b64</a><br>
								Clash: <a href="https://${url.hostname}/${token}?clash" target="_blank" style="color: #1976D2;">https://${url.hostname}/${token}?clash</a><br>
								SingBox: <a href="https://${url.hostname}/${token}?sb" target="_blank" style="color: #1976D2;">https://${url.hostname}/${token}?sb</a><br>
								Surge: <a href="https://${url.hostname}/${token}?surge" target="_blank" style="color: #1976D2;">https://${url.hostname}/${token}?surge</a><br>
								Loon: <a href="https://${url.hostname}/${token}?loon" target="_blank" style="color: #1976D2;">https://${url.hostname}/${token}?loon</a>
							</div>
							<button onclick="editLink('${token}')" style="background: #2196F3; color: white; border: none; padding: 5px 10px; border-radius: 4px; cursor: pointer; margin-top: 5px;">编辑LINK</button>
							<button onclick="deleteSub('${token}')" style="background: #f44336; color: white; border: none; padding: 5px 10px; border-radius: 4px; cursor: pointer; margin-top: 5px; margin-left: 5px;">删除订阅</button>
						</div>
					</div>
				`;
			}).join('');
		} else {
			subscriptionsHtml = '<p>暂无其他订阅</p>';
		}
		
		const html = `
			<!DOCTYPE html>
			<html>
				<head>
					<title>${FileName} 订阅管理</title>
					<meta charset="utf-8">
					<meta name="viewport" content="width=device-width, initial-scale=1">
					<style>
						body {
							margin: 0;
							padding: 15px;
							box-sizing: border-box;
							font-size: 13px;
						}
						.manage-container {
							max-width: 800px;
							margin: 0 auto;
						}
						.create-section {
							border: 1px solid #4CAF50;
							padding: 15px;
							margin: 15px 0;
							border-radius: 4px;
							background: #f1f8f4;
						}
						.create-input {
							width: 300px;
							padding: 8px;
							border: 1px solid #ccc;
							border-radius: 4px;
							margin-right: 10px;
						}
						.create-btn {
							background: #4CAF50;
							color: white;
							border: none;
							padding: 8px 15px;
							border-radius: 4px;
							cursor: pointer;
						}
						.create-btn:hover {
							background: #45a049;
						}
						.subscription-item {
							border: 1px solid #ccc;
							padding: 10px;
							margin: 10px 0;
							border-radius: 4px;
							background: #f9f9f9;
						}
						.delete-btn {
							background: #f44336;
							color: white;
							border: none;
							padding: 5px 10px;
							border-radius: 4px;
							cursor: pointer;
							margin-top: 5px;
						}
						.delete-btn:hover {
							background: #da190b;
						}
						.back-link {
							display: inline-block;
							margin-top: 15px;
							color: #666;
							text-decoration: none;
						}
						.back-link:hover {
							color: #000;
						}
						.link-input-section {
							margin-top: 10px;
						}
						.link-display-section {
							margin-top: 10px;
						}
					</style>
				</head>
				<body>
					<div class="manage-container">
						<h2>${FileName} 订阅管理</h2>
						<p>主管理Token: <strong>${mytoken}</strong>（可通过环境变量TOKEN配置）</p>
						<p style="color: #666; font-size: 12px; margin-top: 5px;">
							提示：Token不能与主管理Token相同，不能包含特殊字符（/、?、&、#）
						</p>
						
						<div class="create-section">
							<h3>创建新订阅</h3>
							<input type="text" id="newToken" class="create-input" placeholder="输入新的Token名称（不能与主Token冲突）">
							<button class="create-btn" onclick="createSub()">创建订阅</button>
							<span id="createStatus" style="margin-left: 10px;"></span>
						</div>
						
						<h3>所有订阅列表</h3>
						<div id="subscriptions">
							${subscriptionsHtml}
						</div>
						
						<a href="https://${url.hostname}/${mytoken}" class="back-link">← 返回主订阅编辑</a>
					</div>
					
					<script>
						async function createSub() {
							const newToken = document.getElementById('newToken').value.trim();
							if (!newToken) {
								alert('请输入Token名称');
								return;
							}
							
							// 前端验证：检查特殊字符
							if (newToken.includes('/') || newToken.includes('?') || newToken.includes('&') || newToken.includes('#')) {
								alert('Token不能包含特殊字符（/、?、&、#）');
								return;
							}
							
							// 前端验证：检查是否为主token（从页面获取）
							const mainToken = '${mytoken}';
							if (newToken === mainToken) {
								alert('Token不能与主管理Token相同');
								return;
							}
							
							const statusElem = document.getElementById('createStatus');
							statusElem.textContent = '创建中...';
							statusElem.style.color = '#666';
							
							try {
								const response = await fetch(window.location.href + '&action=create', {
									method: 'POST',
									body: newToken,
									headers: {
										'Content-Type': 'text/plain;charset=UTF-8'
									}
								});
								
								const result = await response.text();
								if (response.ok) {
									statusElem.textContent = '创建成功！';
									statusElem.style.color = '#4CAF50';
									const tokenValue = newToken;
									document.getElementById('newToken').value = '';
									
									// 动态添加新token的输入框，不刷新页面
									const subscriptionsDiv = document.getElementById('subscriptions');
									const hostname = window.location.hostname;
									
									const newTokenHtml = \`
										<div style="border: 1px solid #ccc; padding: 15px; margin: 10px 0; border-radius: 4px; background: #f9f9f9;">
											<strong>Token: \${tokenValue}</strong><br><br>
											<div id="linkInput_\${tokenValue}" style="">
												<label style="display: block; margin-bottom: 5px; font-weight: bold;">输入LINK（节点链接或订阅链接，每行一个）:</label>
												<textarea id="linkContent_\${tokenValue}" rows="5" style="width: 100%; padding: 8px; border: 1px solid #ccc; border-radius: 4px; font-size: 13px; box-sizing: border-box;" placeholder="vless://...&#10;vmess://...&#10;https://sub.example.com"></textarea>
												<button onclick="saveLink('\${tokenValue}')" style="background: #4CAF50; color: white; border: none; padding: 6px 15px; border-radius: 4px; cursor: pointer; margin-top: 5px;">保存LINK</button>
												<span id="saveStatus_\${tokenValue}" style="margin-left: 10px;"></span>
											</div>
											<div id="linkDisplay_\${tokenValue}" style="display: none;">
												<strong>订阅链接:</strong><br>
												<div style="background: #fff; padding: 10px; margin: 5px 0; border-radius: 4px; border: 1px solid #ddd;">
													自适应: <a href="https://\${hostname}/\${tokenValue}" target="_blank" style="color: #1976D2;">https://\${hostname}/\${tokenValue}</a><br>
													Base64: <a href="https://\${hostname}/\${tokenValue}?b64" target="_blank" style="color: #1976D2;">https://\${hostname}/\${tokenValue}?b64</a><br>
													Clash: <a href="https://\${hostname}/\${tokenValue}?clash" target="_blank" style="color: #1976D2;">https://\${hostname}/\${tokenValue}?clash</a><br>
													SingBox: <a href="https://\${hostname}/\${tokenValue}?sb" target="_blank" style="color: #1976D2;">https://\${hostname}/\${tokenValue}?sb</a><br>
													Surge: <a href="https://\${hostname}/\${tokenValue}?surge" target="_blank" style="color: #1976D2;">https://\${hostname}/\${tokenValue}?surge</a><br>
													Loon: <a href="https://\${hostname}/\${tokenValue}?loon" target="_blank" style="color: #1976D2;">https://\${hostname}/\${tokenValue}?loon</a>
												</div>
												<button onclick="editLink('\${tokenValue}')" style="background: #2196F3; color: white; border: none; padding: 5px 10px; border-radius: 4px; cursor: pointer; margin-top: 5px;">编辑LINK</button>
												<button onclick="deleteSub('\${tokenValue}')" style="background: #f44336; color: white; border: none; padding: 5px 10px; border-radius: 4px; cursor: pointer; margin-top: 5px; margin-left: 5px;">删除订阅</button>
											</div>
										</div>
									\`;
									
									// 如果订阅列表为空，先移除提示
									if (subscriptionsDiv.innerHTML.includes('暂无其他订阅')) {
										subscriptionsDiv.innerHTML = '';
									}
									
									// 添加新token的HTML到列表顶部
									subscriptionsDiv.insertAdjacentHTML('afterbegin', newTokenHtml);
								} else {
									statusElem.textContent = '创建失败: ' + result;
									statusElem.style.color = '#f44336';
								}
							} catch (error) {
								statusElem.textContent = '创建失败: ' + error.message;
								statusElem.style.color = '#f44336';
							}
						}
						
						async function saveLink(token) {
							const linkContent = document.getElementById('linkContent_' + token).value;
							const statusElem = document.getElementById('saveStatus_' + token);
							
							statusElem.textContent = '保存中...';
							statusElem.style.color = '#666';
							
							try {
								const response = await fetch(window.location.href + '&action=saveLink&token=' + token, {
									method: 'POST',
									body: linkContent,
									headers: {
										'Content-Type': 'text/plain;charset=UTF-8'
									}
								});
								
								const result = await response.text();
								if (response.ok) {
									statusElem.textContent = '保存成功！';
									statusElem.style.color = '#4CAF50';
									// 隐藏输入框，显示链接
									document.getElementById('linkInput_' + token).style.display = 'none';
									document.getElementById('linkDisplay_' + token).style.display = 'block';
								} else {
									statusElem.textContent = '保存失败: ' + result;
									statusElem.style.color = '#f44336';
								}
							} catch (error) {
								statusElem.textContent = '保存失败: ' + error.message;
								statusElem.style.color = '#f44336';
							}
						}
						
						function editLink(token) {
							// 显示输入框，隐藏链接显示
							document.getElementById('linkInput_' + token).style.display = 'block';
							document.getElementById('linkDisplay_' + token).style.display = 'none';
							// textarea中已经有内容了（服务端渲染时填充的）
						}
						
						async function deleteSub(token) {
							if (!confirm('确定要删除订阅 "' + token + '" 吗？此操作不可恢复！')) {
								return;
							}
							
							try {
								const response = await fetch(window.location.href + '&action=delete', {
									method: 'POST',
									body: token,
									headers: {
										'Content-Type': 'text/plain;charset=UTF-8'
									}
								});
								
								const result = await response.text();
								if (response.ok) {
									alert('删除成功！');
									location.reload();
								} else {
									alert('删除失败: ' + result);
								}
							} catch (error) {
								alert('删除失败: ' + error.message);
							}
						}
					</script>
				</body>
			</html>
		`;
		
		return new Response(html, {
			headers: { "Content-Type": "text/html;charset=utf-8" }
		});
	} catch (error) {
		console.error('管理订阅时发生错误:', error);
		return new Response("服务器错误: " + error.message, {
			status: 500,
			headers: { "Content-Type": "text/plain;charset=utf-8" }
		});
	}
}

async function KV(request, env, txt = 'ADD.txt', guest, currentToken = null, isMainToken = false, mytoken = 'auto', FileName = 'CF-Workers-SUB', subProtocol = 'https', subConverter = 'SUBAPI.cmliussss.net', subConfig = '') {
	const url = new URL(request.url);
	const token = currentToken || 'auto';
	
	try {
		// POST请求处理
		if (request.method === "POST") {
			if (!env.KV) return new Response("未绑定KV空间", { status: 400 });
			try {
				const content = await request.text();
				await env.KV.put(txt, content);
				return new Response("保存成功");
			} catch (error) {
				console.error('保存KV时发生错误:', error);
				return new Response("保存失败: " + error.message, { status: 500 });
			}
		}

		// GET请求部分
		let content = '';
		let hasKV = !!env.KV;

		if (hasKV) {
			try {
				content = await env.KV.get(txt) || '';
			} catch (error) {
				console.error('读取KV时发生错误:', error);
				content = '读取数据时发生错误: ' + error.message;
			}
		}

		const html = `
			<!DOCTYPE html>
			<html>
				<head>
					<title>${FileName} 订阅编辑</title>
					<meta charset="utf-8">
					<meta name="viewport" content="width=device-width, initial-scale=1">
					<style>
						body {
							margin: 0;
							padding: 15px; /* 调整padding */
							box-sizing: border-box;
							font-size: 13px; /* 设置全局字体大小 */
						}
						.editor-container {
							width: 100%;
							max-width: 100%;
							margin: 0 auto;
						}
						.editor {
							width: 100%;
							height: 300px; /* 调整高度 */
							margin: 15px 0; /* 调整margin */
							padding: 10px; /* 调整padding */
							box-sizing: border-box;
							border: 1px solid #ccc;
							border-radius: 4px;
							font-size: 13px;
							line-height: 1.5;
							overflow-y: auto;
							resize: none;
						}
						.save-container {
							margin-top: 8px; /* 调整margin */
							display: flex;
							align-items: center;
							gap: 10px; /* 调整gap */
						}
						.save-btn, .back-btn {
							padding: 6px 15px; /* 调整padding */
							color: white;
							border: none;
							border-radius: 4px;
							cursor: pointer;
						}
						.save-btn {
							background: #4CAF50;
						}
						.save-btn:hover {
							background: #45a049;
						}
						.back-btn {
							background: #666;
						}
						.back-btn:hover {
							background: #555;
						}
						.save-status {
							color: #666;
						}
					</style>
					<script src="https://cdn.jsdelivr.net/npm/@keeex/qrcodejs-kx@1.0.2/qrcode.min.js"></script>
				</head>
				<body>
					${isMainToken ? `<div style="background: #e3f2fd; padding: 10px; margin: 10px 0; border-radius: 4px; border-left: 4px solid #2196F3;">
						<strong>主管理Token</strong> | 
						<a href="https://${url.hostname}/${mytoken}?manage" style="color: #1976D2; text-decoration: underline;">管理所有订阅</a>
					</div>` : ''}
					################################################################<br>
					Subscribe / sub 订阅地址, 点击链接自动 <strong>复制订阅链接</strong> 并 <strong>生成订阅二维码</strong> <br>
					---------------------------------------------------------------<br>
					当前订阅Token: <strong>${token}</strong><br>
					---------------------------------------------------------------<br>
					自适应订阅地址:<br>
					<a href="javascript:void(0)" onclick="copyToClipboard('https://${url.hostname}/${token}?sub','qrcode_0')" style="color:blue;text-decoration:underline;cursor:pointer;">https://${url.hostname}/${token}</a><br>
					<div id="qrcode_0" style="margin: 10px 10px 10px 10px;"></div>
					Base64订阅地址:<br>
					<a href="javascript:void(0)" onclick="copyToClipboard('https://${url.hostname}/${token}?b64','qrcode_1')" style="color:blue;text-decoration:underline;cursor:pointer;">https://${url.hostname}/${token}?b64</a><br>
					<div id="qrcode_1" style="margin: 10px 10px 10px 10px;"></div>
					clash订阅地址:<br>
					<a href="javascript:void(0)" onclick="copyToClipboard('https://${url.hostname}/${token}?clash','qrcode_2')" style="color:blue;text-decoration:underline;cursor:pointer;">https://${url.hostname}/${token}?clash</a><br>
					<div id="qrcode_2" style="margin: 10px 10px 10px 10px;"></div>
					singbox订阅地址:<br>
					<a href="javascript:void(0)" onclick="copyToClipboard('https://${url.hostname}/${token}?sb','qrcode_3')" style="color:blue;text-decoration:underline;cursor:pointer;">https://${url.hostname}/${token}?sb</a><br>
					<div id="qrcode_3" style="margin: 10px 10px 10px 10px;"></div>
					surge订阅地址:<br>
					<a href="javascript:void(0)" onclick="copyToClipboard('https://${url.hostname}/${token}?surge','qrcode_4')" style="color:blue;text-decoration:underline;cursor:pointer;">https://${url.hostname}/${token}?surge</a><br>
					<div id="qrcode_4" style="margin: 10px 10px 10px 10px;"></div>
					loon订阅地址:<br>
					<a href="javascript:void(0)" onclick="copyToClipboard('https://${url.hostname}/${token}?loon','qrcode_5')" style="color:blue;text-decoration:underline;cursor:pointer;">https://${url.hostname}/${token}?loon</a><br>
					<div id="qrcode_5" style="margin: 10px 10px 10px 10px;"></div>
					&nbsp;&nbsp;<strong><a href="javascript:void(0);" id="noticeToggle" onclick="toggleNotice()">查看访客订阅∨</a></strong><br>
					<div id="noticeContent" class="notice-content" style="display: none;">
						---------------------------------------------------------------<br>
						访客订阅只能使用订阅功能，无法查看配置页！<br>
						GUEST（访客订阅TOKEN）: <strong>${guest}</strong><br>
						---------------------------------------------------------------<br>
						自适应订阅地址:<br>
						<a href="javascript:void(0)" onclick="copyToClipboard('https://${url.hostname}/sub?token=${guest}','guest_0')" style="color:blue;text-decoration:underline;cursor:pointer;">https://${url.hostname}/sub?token=${guest}</a><br>
						<div id="guest_0" style="margin: 10px 10px 10px 10px;"></div>
						Base64订阅地址:<br>
						<a href="javascript:void(0)" onclick="copyToClipboard('https://${url.hostname}/sub?token=${guest}&b64','guest_1')" style="color:blue;text-decoration:underline;cursor:pointer;">https://${url.hostname}/sub?token=${guest}&b64</a><br>
						<div id="guest_1" style="margin: 10px 10px 10px 10px;"></div>
						clash订阅地址:<br>
						<a href="javascript:void(0)" onclick="copyToClipboard('https://${url.hostname}/sub?token=${guest}&clash','guest_2')" style="color:blue;text-decoration:underline;cursor:pointer;">https://${url.hostname}/sub?token=${guest}&clash</a><br>
						<div id="guest_2" style="margin: 10px 10px 10px 10px;"></div>
						singbox订阅地址:<br>
						<a href="javascript:void(0)" onclick="copyToClipboard('https://${url.hostname}/sub?token=${guest}&sb','guest_3')" style="color:blue;text-decoration:underline;cursor:pointer;">https://${url.hostname}/sub?token=${guest}&sb</a><br>
						<div id="guest_3" style="margin: 10px 10px 10px 10px;"></div>
						surge订阅地址:<br>
						<a href="javascript:void(0)" onclick="copyToClipboard('https://${url.hostname}/sub?token=${guest}&surge','guest_4')" style="color:blue;text-decoration:underline;cursor:pointer;">https://${url.hostname}/sub?token=${guest}&surge</a><br>
						<div id="guest_4" style="margin: 10px 10px 10px 10px;"></div>
						loon订阅地址:<br>
						<a href="javascript:void(0)" onclick="copyToClipboard('https://${url.hostname}/sub?token=${guest}&loon','guest_5')" style="color:blue;text-decoration:underline;cursor:pointer;">https://${url.hostname}/sub?token=${guest}&loon</a><br>
						<div id="guest_5" style="margin: 10px 10px 10px 10px;"></div>
					</div>
					---------------------------------------------------------------<br>
					################################################################<br>
					订阅转换配置<br>
					---------------------------------------------------------------<br>
					SUBAPI（订阅转换后端）: <strong>${subProtocol}://${subConverter}</strong><br>
					SUBCONFIG（订阅转换配置文件）: <strong>${subConfig}</strong><br>
					---------------------------------------------------------------<br>
					################################################################<br>
					${FileName} 汇聚订阅编辑: 
					<div class="editor-container">
						${hasKV ? `
						<textarea class="editor" 
							placeholder="${decodeURIComponent(atob('TElOSyVFNyVBNCVCQSVFNCVCRSU4QiVFRiVCQyU4OCVFNCVCOCU4MCVFOCVBMSU4QyVFNCVCOCU4MCVFNCVCOCVBQSVFOCU4QSU4MiVFNyU4MiVCOSVFOSU5MyVCRSVFNiU4RSVBNSVFNSU4RCVCMyVFNSU4RiVBRiVFRiVCQyU4OSVFRiVCQyU5QQp2bGVzcyUzQSUyRiUyRjI0NmFhNzk1LTA2MzctNGY0Yy04ZjY0LTJjOGZiMjRjMWJhZCU0MDEyNy4wLjAuMSUzQTEyMzQlM0ZlbmNyeXB0aW9uJTNEbm9uZSUyNnNlY3VyaXR5JTNEdGxzJTI2c25pJTNEVEcuQ01MaXVzc3NzLmxvc2V5b3VyaXAuY29tJTI2YWxsb3dJbnNlY3VyZSUzRDElMjZ0eXBlJTNEd3MlMjZob3N0JTNEVEcuQ01MaXVzc3NzLmxvc2V5b3VyaXAuY29tJTI2cGF0aCUzRCUyNTJGJTI1M0ZlZCUyNTNEMjU2MCUyM0NGbmF0CnRyb2phbiUzQSUyRiUyRmFhNmRkZDJmLWQxY2YtNGE1Mi1iYTFiLTI2NDBjNDFhNzg1NiU0MDIxOC4xOTAuMjMwLjIwNyUzQTQxMjg4JTNGc2VjdXJpdHklM0R0bHMlMjZzbmklM0RoazEyLmJpbGliaWxpLmNvbSUyNmFsbG93SW5zZWN1cmUlM0QxJTI2dHlwZSUzRHRjcCUyNmhlYWRlclR5cGUlM0Rub25lJTIzSEsKc3MlM0ElMkYlMkZZMmhoWTJoaE1qQXRhV1YwWmkxd2IyeDVNVE13TlRveVJYUlFjVzQyU0ZscVZVNWpTRzlvVEdaVmNFWlJkMjVtYWtORFVUVnRhREZ0U21SRlRVTkNkV04xVjFvNVVERjFaR3RTUzBodVZuaDFielUxYXpGTFdIb3lSbTgyYW5KbmRERTRWelkyYjNCMGVURmxOR0p0TVdwNlprTm1RbUklMjUzRCU0MDg0LjE5LjMxLjYzJTNBNTA4NDElMjNERQoKCiVFOCVBRSVBMiVFOSU5OCU4NSVFOSU5MyVCRSVFNiU4RSVBNSVFNyVBNCVCQSVFNCVCRSU4QiVFRiVCQyU4OCVFNCVCOCU4MCVFOCVBMSU4QyVFNCVCOCU4MCVFNiU5RCVBMSVFOCVBRSVBMiVFOSU5OCU4NSVFOSU5MyVCRSVFNiU4RSVBNSVFNSU4RCVCMyVFNSU4RiVBRiVFRiVCQyU4OSVFRiVCQyU5QQpodHRwcyUzQSUyRiUyRnN1Yi54Zi5mcmVlLmhyJTJGYXV0bw=='))}"
							id="content">${content}</textarea>
						<div class="save-container">
							<button class="save-btn" onclick="saveContent(this)">保存</button>
							<span class="save-status" id="saveStatus"></span>
						</div>
						` : '<p>请绑定 <strong>变量名称</strong> 为 <strong>KV</strong> 的KV命名空间</p>'}
					</div>
					<br>
					################################################################<br>
					${decodeURIComponent(atob('LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tJTNDYnIlM0UlMEFnaXRodWIlMjAlRTklQTElQjklRTclOUIlQUUlRTUlOUMlQjAlRTUlOUQlODAlMjBTdGFyIVN0YXIhU3RhciEhISUzQ2JyJTNFJTBBJTNDYSUyMGhyZWYlM0QlMjJodHRwcyUzQSUyRiUyRmdpdGh1Yi5jb20lMkZBc1plcjBzJTJGQ0YtV29ya2Vycy1TVUIlMjIlMjB0YXJnZXQlM0QlMjJfYmxhbmslMjIlMjBzdHlsZSUzRCUyMmNvbG9yJTNBJTIwJTIzMTk3NkQyJTNCJTIyJTNFaHR0cHMlM0ElMkYlMkZnaXRodWIuY29tJTJGQXNaZXIwcyUyRkNGLVdvcmtlcnMtU1VCJTNDJTJGYSUzRSUzQ2JyJTNFJTBBJUU2JTg0JTlGJUU4JUIwJUEyJUU0JUI4JThBJUU2JUI4JUI4JUU0JUJCJTkzJUU1JUJBJTkzJTNDYnIlM0UlMEElM0NhJTIwaHJlZiUzRCUyMmh0dHBzJTNBJTJGJTJGZ2l0aHViLmNvbSUyRmNtbGl1JTJGQ0YtV29ya2Vycy1TVUIlMjIlMjB0YXJnZXQlM0QlMjJfYmxhbmslMjIlMjBzdHlsZSUzRCUyMmNvbG9yJTNBJTIwJTIzMTk3NkQyJTNCJTIyJTNFaHR0cHMlM0ElMkYlMkZnaXRodWIuY29tJTJGY21saXUlMkZDRi1Xb3JrZXJzLVNVQiUzQyUyRmElM0UlM0NiciUzRSUwQS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQ=='))}
					<br>################################################################<br>
					<br><br>UA: <strong>${request.headers.get('User-Agent')}</strong>
					<script>
					function copyToClipboard(text, qrcode) {
						navigator.clipboard.writeText(text).then(() => {
							alert('已复制到剪贴板');
						}).catch(err => {
							console.error('复制失败:', err);
						});
						const qrcodeDiv = document.getElementById(qrcode);
						qrcodeDiv.innerHTML = '';
						new QRCode(qrcodeDiv, {
							text: text,
							width: 220, // 调整宽度
							height: 220, // 调整高度
							colorDark: "#000000", // 二维码颜色
							colorLight: "#ffffff", // 背景颜色
							correctLevel: QRCode.CorrectLevel.Q, // 设置纠错级别
							scale: 1 // 调整像素颗粒度
						});
					}
						
					if (document.querySelector('.editor')) {
						let timer;
						const textarea = document.getElementById('content');
						const originalContent = textarea.value;
		
						function goBack() {
							const currentUrl = window.location.href;
							const parentUrl = currentUrl.substring(0, currentUrl.lastIndexOf('/'));
							window.location.href = parentUrl;
						}
		
						function replaceFullwidthColon() {
							const text = textarea.value;
							textarea.value = text.replace(/：/g, ':');
						}
						
						function saveContent(button) {
							try {
								const updateButtonText = (step) => {
									button.textContent = \`保存中: \${step}\`;
								};
								// 检测是否为iOS设备
								const isIOS = /iPad|iPhone|iPod/.test(navigator.userAgent);
								
								// 仅在非iOS设备上执行replaceFullwidthColon
								if (!isIOS) {
									replaceFullwidthColon();
								}
								updateButtonText('开始保存');
								button.disabled = true;

								// 获取textarea内容和原始内容
								const textarea = document.getElementById('content');
								if (!textarea) {
									throw new Error('找不到文本编辑区域');
								}

								updateButtonText('获取内容');
								let newContent;
								let originalContent;
								try {
									newContent = textarea.value || '';
									originalContent = textarea.defaultValue || '';
								} catch (e) {
									console.error('获取内容错误:', e);
									throw new Error('无法获取编辑内容');
								}

								updateButtonText('准备状态更新函数');
								const updateStatus = (message, isError = false) => {
									const statusElem = document.getElementById('saveStatus');
									if (statusElem) {
										statusElem.textContent = message;
										statusElem.style.color = isError ? 'red' : '#666';
									}
								};

								updateButtonText('准备按钮重置函数');
								const resetButton = () => {
									button.textContent = '保存';
									button.disabled = false;
								};

								if (newContent !== originalContent) {
									updateButtonText('发送保存请求');
									fetch(window.location.href, {
										method: 'POST',
										body: newContent,
										headers: {
											'Content-Type': 'text/plain;charset=UTF-8'
										},
										cache: 'no-cache'
									})
									.then(response => {
										updateButtonText('检查响应状态');
										if (!response.ok) {
											throw new Error(\`HTTP error! status: \${response.status}\`);
										}
										updateButtonText('更新保存状态');
										const now = new Date().toLocaleString();
										document.title = \`编辑已保存 \${now}\`;
										updateStatus(\`已保存 \${now}\`);
									})
									.catch(error => {
										updateButtonText('处理错误');
										console.error('Save error:', error);
										updateStatus(\`保存失败: \${error.message}\`, true);
									})
									.finally(() => {
										resetButton();
									});
								} else {
									updateButtonText('检查内容变化');
									updateStatus('内容未变化');
									resetButton();
								}
							} catch (error) {
								console.error('保存过程出错:', error);
								button.textContent = '保存';
								button.disabled = false;
								const statusElem = document.getElementById('saveStatus');
								if (statusElem) {
									statusElem.textContent = \`错误: \${error.message}\`;
									statusElem.style.color = 'red';
								}
							}
						}
		
						textarea.addEventListener('blur', saveContent);
						textarea.addEventListener('input', () => {
							clearTimeout(timer);
							timer = setTimeout(saveContent, 5000);
						});
					}

					function toggleNotice() {
						const noticeContent = document.getElementById('noticeContent');
						const noticeToggle = document.getElementById('noticeToggle');
						if (noticeContent.style.display === 'none' || noticeContent.style.display === '') {
							noticeContent.style.display = 'block';
							noticeToggle.textContent = '隐藏访客订阅∧';
						} else {
							noticeContent.style.display = 'none';
							noticeToggle.textContent = '查看访客订阅∨';
						}
					}
			
					// 初始化 noticeContent 的 display 属性
					document.addEventListener('DOMContentLoaded', () => {
						document.getElementById('noticeContent').style.display = 'none';
					});
					</script>
				</body>
			</html>
		`;

		return new Response(html, {
			headers: { "Content-Type": "text/html;charset=utf-8" }
		});
	} catch (error) {
		console.error('处理请求时发生错误:', error);
		return new Response("服务器错误: " + error.message, {
			status: 500,
			headers: { "Content-Type": "text/plain;charset=utf-8" }
		});
	}
}