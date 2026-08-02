# ☁️ Cloudflare cable



A super simple, ultra-lightweight FIDO caBLE tunnel server running entirely on Cloudflare Workers and Durable Objects.

`cloudflare_caBLE` provides you with an out-of-the-box, serverless passkey tunnel.


## ✨ Features (Why Use It)

* **🚀 Blazing Fast:** Runs on Cloudflare's edge network. This "tunnel" is always established at the node closest to your physical location.
* **🛠️ Zero Server Maintenance:** No need to worry about Linux upgrades or restarting Docker containers. It is completely serverless—set it and forget it.

## ⚠️ Compliance and Disclaimer

The code is provided 'as is', and the developers assume no liability for any misuse, damages, or legal consequences arising from its deployment.

This project is intended solely for academic research and technical exchange regarding FIDO/WebAuthn cryptographic protocols, demonstrating the implementation principles of caBLE.

Users must use this project in strict compliance with local laws and regulations. It is strictly prohibited to modify or use this code for any form of illegal activity.


## 🚀 Quick Start

Simply modify the code and deploy it yourself. In Cloudflare Workers & Pages, select **Continue with GitHub**.

### Configuration (How to use your own domain)


```toml
routes = [
  { pattern = "cable.yourdomain.com", custom_domain = true } 
]

```

## 🙏 Acknowledgments

This project is made possible thanks to the incredible infrastructure and open standards provided by:

* **[Cloudflare](https://www.cloudflare.com/)**: For providing the blazing-fast edge network, Workers, and Durable Objects infrastructure that powers this serverless tunnel.
* **[FIDO Alliance](https://fidoalliance.org/)**: For developing and maintaining the open FIDO2/WebAuthn and caBLE protocol specifications that secure the modern web.

---

Thanks to [GitHub](https://github.com/) and [Linux do](https://linux.do/).