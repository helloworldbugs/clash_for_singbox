import { createApp, ref, nextTick } from "./vue.esm-browser.prod.mjs"
import { Base64 } from "./base64.min.mjs"

// Compression Stream API 辅助函数
async function compressString(str) {
    const encoder = new TextEncoder();
    const inputStream = new ReadableStream({
        start(controller) {
            controller.enqueue(encoder.encode(str));
            controller.close();
        }
    });

    const compressedStream = inputStream.pipeThrough(new CompressionStream('deflate'));
    const compressedArray = await new Response(compressedStream).arrayBuffer();
    return new Uint8Array(compressedArray);
}

function defaultProxyGroups() {
    return [
        { tag: "urltest", type: "urltest", include: ".*", exclude: "", srsUrl: "" },
        { tag: "select", type: "selector", include: ".*", exclude: "", srsUrl: "" }
    ]
}

async function decompressString(compressedData) {
    const inputStream = new ReadableStream({
        start(controller) {
            controller.enqueue(compressedData);
            controller.close();
        }
    });

    const decompressedStream = inputStream.pipeThrough(new DecompressionStream('deflate'));
    const decompressedArray = await new Response(decompressedStream).arrayBuffer();
    const decoder = new TextDecoder();
    return decoder.decode(decompressedArray);
}


createApp({
    setup(props, context) {
        const sub = ref('');
        const newsub = ref('');
        const config = ref('加载中');
        const configurl = ref('');
        const inFetch = ref(false)
        const inputRef = ref(null)
        const addTag = ref(false)
        const outFields = ref("0")
        const configType = ref("4")
        const proxyGroups = ref(defaultProxyGroups())


        let oldConfig = "";

        (async () => {
            const f = await fetch("/config/config.json-1.12.0+.template?" + window.version ?? "")
            config.value = await f.text()
            oldConfig = config.value
            onChange()
        })();

        async function saveParameter() {
            const subUrl = new URL(new URL(location.href).origin)
            subUrl.pathname = "/sub"
            const c = config.value != oldConfig ? config.value : ""
            if (c != "") {
                const compressed = await compressString(config.value);
                const base64String = Base64.fromUint8Array(compressed, true)
                subUrl.searchParams.set("config", base64String)
            }
            configurl.value && subUrl.searchParams.set("configurl", configurl.value)
            addTag.value && subUrl.searchParams.set("addTag", "true")
            subUrl.searchParams.set("outFields", outFields.value || "0")
            if (proxyGroups.value.length > 0) {
                const groupString = JSON.stringify(proxyGroups.value)
                const compressed = await compressString(groupString)
                const base64String = Base64.fromUint8Array(compressed, true)
                subUrl.searchParams.set("proxyGroups", base64String)
            }
            subUrl.searchParams.set("sub", sub.value)
            return subUrl.toString()
        }


        function catchSome(f, onfail) {
            const nf = async (...a) => {
                try {
                    return await f(...a);
                } catch (e) {
                    if (onfail) {
                        onfail()
                    }
                    console.warn(e)
                    alert(String(e))
                }
            }
            return nf
        }



        const click = catchSome(async () => {
            if (sub.value == "") {
                return ""
            }
            if (inFetch.value) {
                return
            }
            newsub.value = ""
            inFetch.value = true
            const subURL = await saveParameter()
            const f = await fetch(subURL)
            if (!f.ok) {
                const msg = await f.text()
                newsub.value = msg
                console.warn(msg)
                inFetch.value = false
                alert("错误 " + msg)
                return
            }
            inFetch.value = false
            newsub.value = subURL
            await nextTick()
            inputRef.value.scrollIntoView({ behavior: "smooth" })
            inputRef.value.select()
            document.execCommand('copy', true);
            const sing = new URL("sing-box://import-remote-profile")
            sing.searchParams.set("url", subURL)
            window.location.href = sing.toString()
        }, () => {
            inFetch.value = false
        })


        document.addEventListener('paste', async (event) => {
            const items = event.clipboardData && event.clipboardData.items;
            for (const v of items) {
                if (v.kind == "file") continue

                v.getAsString(async (str) => {
                    try {
                        const u = new URL(str)
                        if (u.pathname != "/sub") {
                            return
                        }
                        if (!confirm("解析粘贴的订阅链接？")) {
                            return
                        }
                        const c = u.searchParams.get("config")
                        if (c && c != "") {
                            const d = await decompressString(Base64.toUint8Array(c));
                            configType.value = "2"
                            config.value = d
                        }
                        const cu = u.searchParams.get("configurl")
                        if (cu && cu != "") {
                            configurl.value = cu
                            config.value = oldConfig
                            configType.value = "3"
                        } else {
                            configurl.value = ""
                        }
                        sub.value = u.searchParams.get("sub") || sub.value
                        addTag.value = u.searchParams.get("addTag") === "true"
                        outFields.value = u.searchParams.get("outFields") || outFields.value
                        const pg = u.searchParams.get("proxyGroups")
                        if (pg && pg !== "") {
                            const pgJson = await decompressString(Base64.toUint8Array(pg))
                            const list = JSON.parse(pgJson)
                            proxyGroups.value = Array.isArray(list) ? list : defaultProxyGroups()
                        } else {
                            proxyGroups.value = defaultProxyGroups()
                        }
                    } catch (error) {
                        console.log(error)
                        return
                    }
                })

            }
        });

        function addProxyGroup() {
            proxyGroups.value.push({
                tag: "",
                type: "urltest",
                include: "",
                exclude: "",
                srsUrl: ""
            })
        }

        function removeProxyGroup(index) {
            proxyGroups.value.splice(index, 1)
        }

        function onChange() {
            if (configType.value != "2") {
                config.value = ""
            }
            if (configType.value != "3") {
                configurl.value = ""
            }
            if (configType.value === "0") {
                configurl.value = "config.json.template"
                outFields.value = "1"
            }
            if (configType.value === "1") {
                configurl.value = "config.json-1.11.0+.template"
                outFields.value = "0"
            }
            if (configType.value === "4") {
                configurl.value = "config.json-1.12.0+.template"
                outFields.value = "0"
            }
            if (configType.value === "2" && config.value == "") {
                config.value = oldConfig
            }
        }

        return {
            sub,
            config,
            newsub,
            click,
            configurl,
            inFetch,
            inputRef,
            addTag,
            outFields,
            configType,
            onChange,
            proxyGroups,
            addProxyGroup,
            removeProxyGroup
        }

    },
}).mount('#app')
