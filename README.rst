Qcloud DNS Authenticator plugin for Certbot
===============================================
This plugin design for user using Certbot to create free Let's Encrypt license
on Qcloud and using Qcloud DNS for authentication challenge. This plugin only
for personal study and internal usage.

Overall coding style based on certbot-dns-google, thanks to contributors of
this project.

Let's Encrypt certbot的腾讯云dns插件

fork自https://github.com/ChuckNg/CertbotAliyunDns,然后对其修改

certbot_dns_qcloud/dns_qcloud.py第15行domain_end,是为了确定域名后缀,可自行添加


Installation
------------
    pip install -e $CWD

Execution
---------
.. code-block:: bash

    $ certbot certonly --certbot-dns-qcloud:dns-qcloud-propagation-seconds 10  \
                       --certbot-dns-qcloud:dns-qcloud-credentials $PATH_TO_CREDENTIALS/qcloud.json \
                       -d "$YOUR_DOMAIN"

Reference
---------
1. certbot-dns-google, https://github.com/certbot/certbot/tree/master/certbot-dns-google
2. Certbot - Developer Guide, https://certbot.eff.org/docs/contributing.html#writing-your-own-plugin
3. Certbot - API Documentation -certbot.plugins.dns_common, https://certbot.eff.org/docs/api/plugins/dns_common.html

Issue
---------
`[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed`

.. code-block:: bash

    $ pip install --upgrade certifi