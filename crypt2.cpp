/*
 * Copyright (C) 2004-2026 ZNC, see the NOTICE file for details.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Based on the original crypt module by prozac@rottenboy.com
// Modified to use AES-256-GCM instead of Blowfish-CBC.
//
// Wire format is identical: +OK *<base64>
// Encrypted payload: [12-byte nonce][ciphertext][16-byte GCM auth tag]
//
// Keys can be set manually with SetKey or exchanged via KeyX (DH1080).
// For manual keys, generate 32 random bytes and base64-encode them:
//   openssl rand -base64 32
// Then: /msg *crypt SetKey <nick/#chan> <that string>
//
// NOTE: Keys are stored in plaintext on disk (same as original).
//       Use SSL between ZNC and your client.

#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <znc/Chan.h>
#include <znc/IRCNetwork.h>
#include <znc/SHA256.h>
#include <znc/User.h>

#define REQUIRESSL 1

#define NICK_PREFIX_OLD_KEY "[nick-prefix]"
#define NICK_PREFIX_KEY "@nick-prefix@"

// AES-256-GCM constants
#define AES_NONCE_LEN 12
#define AES_TAG_LEN   16
#define AES_KEY_LEN   32

// Derive a 32-byte AES key from whatever string the user set.
// If it's already 32+ raw bytes after base64 decoding, use those.
// Otherwise SHA256 the raw string to get 32 bytes.
static bool DeriveKey(const CString& sKey, unsigned char out[AES_KEY_LEN]) {
    // Try base64 decode first
    CString sDecoded = sKey;
    size_t len = sDecoded.Base64Decode();
    if (len >= AES_KEY_LEN) {
        memcpy(out, sDecoded.data(), AES_KEY_LEN);
        return true;
    }
    // Fall back: SHA256 the key string
    sha256((const unsigned char*)sKey.data(), sKey.size(), out);
    return true;
}

static CString AESEncrypt(const CString& sKey, const CString& sPlaintext) {
    unsigned char key[AES_KEY_LEN];
    if (!DeriveKey(sKey, key)) return "";

    unsigned char nonce[AES_NONCE_LEN];
    if (RAND_bytes(nonce, AES_NONCE_LEN) != 1) return "";

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return "";

    int len = 0;
    int ciphertext_len = 0;
    std::vector<unsigned char> ciphertext(sPlaintext.size() + AES_TAG_LEN);

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, nonce) != 1 ||
        EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
                          (const unsigned char*)sPlaintext.data(), sPlaintext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    ciphertext_len += len;

    unsigned char tag[AES_TAG_LEN];
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_TAG_LEN, tag);
    EVP_CIPHER_CTX_free(ctx);

    // Output: nonce + ciphertext + tag
    CString sResult;
    sResult.append((char*)nonce, AES_NONCE_LEN);
    sResult.append((char*)ciphertext.data(), ciphertext_len);
    sResult.append((char*)tag, AES_TAG_LEN);
    return sResult;
}

static CString AESDecrypt(const CString& sKey, const CString& sData) {
    // Minimum: nonce + tag (no empty plaintext check needed, 0-byte messages are valid)
    if (sData.size() < AES_NONCE_LEN + AES_TAG_LEN) return "";

    unsigned char key[AES_KEY_LEN];
    if (!DeriveKey(sKey, key)) return "";

    const unsigned char* nonce      = (const unsigned char*)sData.data();
    const unsigned char* ciphertext = nonce + AES_NONCE_LEN;
    int ciphertext_len              = (int)sData.size() - AES_NONCE_LEN - AES_TAG_LEN;
    const unsigned char* tag        = (const unsigned char*)sData.data() + AES_NONCE_LEN + ciphertext_len;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return "";

    std::vector<unsigned char> plaintext(ciphertext_len);
    int len = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, nonce) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_TAG_LEN, (void*)tag) != 1 ||
        EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext, ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }

    // Final check - this is where GCM authentication happens
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
        // Authentication failed - message tampered or wrong key
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    EVP_CIPHER_CTX_free(ctx);

    return CString((char*)plaintext.data(), ciphertext_len);
}

class CCryptMod : public CModule {
  private:
    static constexpr const char* m_sPrime1080 =
        "FBE1022E23D213E8ACFA9AE8B9DFADA3EA6B7AC7A7B7E95AB5EB2DF858921FEADE95E6"
        "AC7BE7DE6ADBAB8A783E7AF7A7FA6A2B7BEB1E72EAE2B72F9FA2BFB2A2EFBEFAC868BA"
        "DB3E828FA8BADFADA3E4CC1BE7E8AFE85E9698A783EB68FA07A77AB6AD7BEB618ACF9C"
        "A2897EB28A6189EFA07AB99A8A7FA9AE299EFA7BA66DEAFEFBEFBF0B7D8B";

    std::unique_ptr<DH, decltype(&DH_free)> m_pDH;
    CString m_sPrivKey;
    CString m_sPubKey;

#if OPENSSL_VERSION_NUMBER < 0X10100000L || \
    (defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x02070000fL)
    static int DH_set0_pqg(DH* dh, BIGNUM* p, BIGNUM* q, BIGNUM* g) {
        if (dh == nullptr || (dh->p == nullptr && p == nullptr) ||
            (dh->g == nullptr && g == nullptr))
            return 0;
        if (p != nullptr) { BN_free(dh->p); dh->p = p; }
        if (g != nullptr) { BN_free(dh->g); dh->g = g; }
        if (q != nullptr) { BN_free(dh->q); dh->q = q; dh->length = BN_num_bits(q); }
        return 1;
    }
    static void DH_get0_key(const DH* dh, const BIGNUM** pub_key, const BIGNUM** priv_key) {
        if (dh != nullptr) {
            if (pub_key != nullptr)  *pub_key  = dh->pub_key;
            if (priv_key != nullptr) *priv_key = dh->priv_key;
        }
    }
#endif

    bool DH1080_gen() {
        if (m_sPrivKey.empty() || m_sPubKey.empty()) {
            int len;
            const BIGNUM* bPrivKey = nullptr;
            const BIGNUM* bPubKey  = nullptr;
            BIGNUM* bPrime = nullptr;
            BIGNUM* bGen   = nullptr;

            if (!BN_hex2bn(&bPrime, m_sPrime1080) || !BN_dec2bn(&bGen, "2") ||
                !DH_set0_pqg(m_pDH.get(), bPrime, nullptr, bGen) ||
                !DH_generate_key(m_pDH.get())) {
                if (bPrime != nullptr) BN_clear_free(bPrime);
                if (bGen   != nullptr) BN_clear_free(bGen);
                return false;
            }
            DH_get0_key(m_pDH.get(), &bPubKey, &bPrivKey);

            len = BN_num_bytes(bPrivKey);
            m_sPrivKey.resize(len);
            BN_bn2bin(bPrivKey, (unsigned char*)m_sPrivKey.data());
            m_sPrivKey.Base64Encode();

            len = BN_num_bytes(bPubKey);
            m_sPubKey.resize(len);
            BN_bn2bin(bPubKey, (unsigned char*)m_sPubKey.data());
            m_sPubKey.Base64Encode();
        }
        return true;
    }

    bool DH1080_comp(CString& sOtherPubKey, CString& sSecretKey) {
        long len;
        unsigned char* key = nullptr;
        BIGNUM* bOtherPubKey = nullptr;

        len = sOtherPubKey.Base64Decode();
        bOtherPubKey = BN_bin2bn((unsigned char*)sOtherPubKey.data(), len, nullptr);

        key = (unsigned char*)calloc(DH_size(m_pDH.get()), 1);
        if ((len = DH_compute_key(key, bOtherPubKey, m_pDH.get())) == -1) {
            sSecretKey = "";
            if (bOtherPubKey != nullptr) BN_clear_free(bOtherPubKey);
            if (key != nullptr) free(key);
            return false;
        }

        sSecretKey.resize(SHA256_DIGEST_SIZE);
        sha256(key, len, (unsigned char*)sSecretKey.data());
        sSecretKey.Base64Encode();
        sSecretKey.TrimRight("=");

        if (bOtherPubKey != nullptr) BN_clear_free(bOtherPubKey);
        if (key != nullptr) free(key);
        return true;
    }

    CString NickPrefix() {
        MCString::iterator it = FindNV(NICK_PREFIX_KEY);
        CString sStatusPrefix = GetUser()->GetStatusPrefix();
        if (it != EndNV()) {
            size_t sp = sStatusPrefix.size();
            size_t np = it->second.size();
            int min = std::min(sp, np);
            if (min == 0 || sStatusPrefix.CaseCmp(it->second, min) != 0)
                return it->second;
        }
        return sStatusPrefix.StartsWith("*") ? "." : "*";
    }

  public:
    MODCONSTRUCTOR(CCryptMod), m_pDH(DH_new(), DH_free) {
        AddHelpCommand();
        AddCommand("DelKey",  t_d("<#chan|Nick>"),         t_d("Remove a key for nick or channel"),
                   [=](const CString& sLine) { OnDelKeyCommand(sLine); });
        AddCommand("SetKey",  t_d("<#chan|Nick> <Key>"),   t_d("Set a key for nick or channel"),
                   [=](const CString& sLine) { OnSetKeyCommand(sLine); });
        AddCommand("ListKeys", "",                          t_d("List all keys"),
                   [=](const CString& sLine) { OnListKeysCommand(sLine); });
        AddCommand("KeyX",    t_d("<Nick>"),               t_d("Start a DH1080 key exchange with nick"),
                   [=](const CString& sLine) { OnKeyXCommand(sLine); });
        AddCommand("GetNickPrefix", "",                    t_d("Get the nick prefix"),
                   [=](const CString& sLine) { OnGetNickPrefixCommand(sLine); });
        AddCommand("SetNickPrefix", t_d("[Prefix]"),       t_d("Set the nick prefix"),
                   [=](const CString& sLine) { OnSetNickPrefixCommand(sLine); });
    }

    bool OnLoad(const CString& sArgsi, CString& sMessage) override {
        MCString::iterator it = FindNV(NICK_PREFIX_KEY);
        if (it == EndNV()) {
            it = FindNV(NICK_PREFIX_OLD_KEY);
            if (it != EndNV()) {
                SetNV(NICK_PREFIX_KEY, it->second);
                DelNV(NICK_PREFIX_OLD_KEY);
            }
        }
        return true;
    }

    EModRet OnUserTextMessage(CTextMessage& Message)     override { FilterOutgoing(Message); return CONTINUE; }
    EModRet OnUserNoticeMessage(CNoticeMessage& Message) override { FilterOutgoing(Message); return CONTINUE; }
    EModRet OnUserActionMessage(CActionMessage& Message) override { FilterOutgoing(Message); return CONTINUE; }
    EModRet OnUserTopicMessage(CTopicMessage& Message)   override { FilterOutgoing(Message); return CONTINUE; }

    EModRet OnPrivMsg(CNick& Nick, CString& sMessage) override {
        FilterIncoming(Nick.GetNick(), Nick, sMessage);
        return CONTINUE;
    }

    EModRet OnPrivNotice(CNick& Nick, CString& sMessage) override {
        CString sCommand    = sMessage.Token(0);
        CString sOtherPubKey = sMessage.Token(1);

        if ((sCommand.Equals("DH1080_INIT") || sCommand.Equals("DH1080_INIT_CBC")) &&
            !sOtherPubKey.empty()) {
            CString sSecretKey;
            CString sTail = sMessage.Token(2);
            if (sOtherPubKey.TrimSuffix("A") && DH1080_gen() &&
                DH1080_comp(sOtherPubKey, sSecretKey)) {
                PutModule(t_f("Received DH1080 public key from {1}, sending mine...")(Nick.GetNick()));
                PutIRC("NOTICE " + Nick.GetNick() + " :DH1080_FINISH " + m_sPubKey + "A" +
                       (sTail.empty() ? "" : (" " + sTail)));
                SetNV(Nick.GetNick().AsLower(), sSecretKey);
                PutModule(t_f("Key for {1} successfully set.")(Nick.GetNick()));
                return HALT;
            }
            PutModule(t_f("Error in {1} with {2}: {3}")(sCommand, Nick.GetNick(),
                      (sSecretKey.empty() ? t_s("no secret key computed") : sSecretKey)));
            return CONTINUE;
        } else if (sCommand.Equals("DH1080_FINISH") && !sOtherPubKey.empty()) {
            CString sSecretKey;
            if (sOtherPubKey.TrimSuffix("A") && DH1080_gen() &&
                DH1080_comp(sOtherPubKey, sSecretKey)) {
                SetNV(Nick.GetNick().AsLower(), sSecretKey);
                PutModule(t_f("Key for {1} successfully set.")(Nick.GetNick()));
                return HALT;
            }
            PutModule(t_f("Error in {1} with {2}: {3}")(sCommand, Nick.GetNick(),
                      (sSecretKey.empty() ? t_s("no secret key computed") : sSecretKey)));
            return CONTINUE;
        }

        FilterIncoming(Nick.GetNick(), Nick, sMessage);
        return CONTINUE;
    }

    EModRet OnPrivAction(CNick& Nick, CString& sMessage)                  override { FilterIncoming(Nick.GetNick(),      Nick, sMessage); return CONTINUE; }
    EModRet OnChanMsg(CNick& Nick, CChan& Channel, CString& sMessage)     override { FilterIncoming(Channel.GetName(),   Nick, sMessage); return CONTINUE; }
    EModRet OnChanNotice(CNick& Nick, CChan& Channel, CString& sMessage)  override { FilterIncoming(Channel.GetName(),   Nick, sMessage); return CONTINUE; }
    EModRet OnChanAction(CNick& Nick, CChan& Channel, CString& sMessage)  override { FilterIncoming(Channel.GetName(),   Nick, sMessage); return CONTINUE; }
    EModRet OnTopic(CNick& Nick, CChan& Channel, CString& sMessage)       override { FilterIncoming(Channel.GetName(),   Nick, sMessage); return CONTINUE; }

    EModRet OnNumericMessage(CNumericMessage& Message) override {
        if (Message.GetCode() != 332) return CONTINUE;
        CChan* pChan = GetNetwork()->FindChan(Message.GetParam(1));
        if (pChan) {
            CNick* Nick = pChan->FindNick(Message.GetParam(0));
            CString sTopic = Message.GetParam(2);
            FilterIncoming(pChan->GetName(), *Nick, sTopic);
            Message.SetParam(2, sTopic);
        }
        return CONTINUE;
    }

    template <typename T>
    void FilterOutgoing(T& Msg) {
        CString sTarget = Msg.GetTarget();
        sTarget.TrimPrefix(NickPrefix());
        Msg.SetTarget(sTarget);

        CString sMessage = Msg.GetText();
        if (sMessage.TrimPrefix("``")) return;

        MCString::iterator it = FindNV(sTarget.AsLower());
        if (it != EndNV()) {
            CString sEncrypted = AESEncrypt(it->second, sMessage);
            if (sEncrypted.empty()) return;
            sEncrypted.Base64Encode();
            Msg.SetText("+OK *" + sEncrypted);
        }
    }

    void FilterIncoming(const CString& sTarget, CNick& Nick, CString& sMessage) {
        if (sMessage.TrimPrefix("+OK *")) {
            MCString::iterator it = FindNV(sTarget.AsLower());
            if (it != EndNV()) {
                sMessage.Base64Decode();
                CString sDecrypted = AESDecrypt(it->second, sMessage);
                if (sDecrypted.empty()) {
                    sMessage = "(decryption failed - wrong key or tampered message)";
                    return;
                }
                sMessage = sDecrypted;
                Nick.SetNick(NickPrefix() + Nick.GetNick());
            }
        }
    }

    void OnDelKeyCommand(const CString& sCommand) {
        CString sTarget = sCommand.Token(1);
        if (!sTarget.empty()) {
            if (DelNV(sTarget.AsLower()))
                PutModule(t_f("Target [{1}] deleted")(sTarget));
            else
                PutModule(t_f("Target [{1}] not found")(sTarget));
        } else {
            PutModule(t_s("Usage: DelKey <#chan|Nick>"));
        }
    }

    void OnSetKeyCommand(const CString& sCommand) {
        CString sTarget = sCommand.Token(1);
        CString sKey    = sCommand.Token(2, true);
        sKey.TrimPrefix("cbc:");
        if (!sKey.empty()) {
            SetNV(sTarget.AsLower(), sKey);
            PutModule(t_f("Set encryption key for [{1}] to [{2}]")(sTarget, sKey));
        } else {
            PutModule(t_s("Usage: SetKey <#chan|Nick> <Key>"));
        }
    }

    void OnKeyXCommand(const CString& sCommand) {
        CString sTarget = sCommand.Token(1);
        if (!sTarget.empty()) {
            if (DH1080_gen()) {
                PutIRC("NOTICE " + sTarget + " :DH1080_INIT " + m_sPubKey + "A");
                PutModule(t_f("Sent my DH1080 public key to {1}, waiting for reply...")(sTarget));
            } else {
                PutModule(t_s("Error generating our keys, nothing sent."));
            }
        } else {
            PutModule(t_s("Usage: KeyX <Nick>"));
        }
    }

    void OnGetNickPrefixCommand(const CString& sCommand) {
        CString sPrefix = NickPrefix();
        if (sPrefix.empty())
            PutModule(t_s("Nick Prefix disabled."));
        else
            PutModule(t_f("Nick Prefix: {1}")(sPrefix));
    }

    void OnSetNickPrefixCommand(const CString& sCommand) {
        CString sPrefix = sCommand.Token(1);
        if (sPrefix.StartsWith(":")) {
            PutModule(t_s("You cannot use : as Nick Prefix."));
        } else {
            CString sStatusPrefix = GetUser()->GetStatusPrefix();
            size_t sp = sStatusPrefix.size();
            size_t np = sPrefix.size();
            int min = std::min(sp, np);
            if (min > 0 && sStatusPrefix.CaseCmp(sPrefix, min) == 0)
                PutModule(t_f("Overlap with Status Prefix ({1}), this Nick Prefix will not be used!")(sStatusPrefix));
            else {
                SetNV(NICK_PREFIX_KEY, sPrefix);
                if (sPrefix.empty())
                    PutModule(t_s("Disabling Nick Prefix."));
                else
                    PutModule(t_f("Setting Nick Prefix to {1}")(sPrefix));
            }
        }
    }

    void OnListKeysCommand(const CString& sCommand) {
        CTable Table;
        Table.AddColumn(t_s("Target", "listkeys"));
        Table.AddColumn(t_s("Key", "listkeys"));
        Table.SetStyle(CTable::ListStyle);
        for (MCString::iterator it = BeginNV(); it != EndNV(); ++it) {
            if (!it->first.Equals(NICK_PREFIX_KEY)) {
                Table.AddRow();
                Table.SetCell(t_s("Target", "listkeys"), it->first);
                Table.SetCell(t_s("Key",    "listkeys"), it->second);
            }
        }
        if (Table.empty())
            PutModule(t_s("You have no encryption keys set."));
        else
            PutModule(Table);
    }
};

template <>
void TModInfo<CCryptMod>(CModInfo& Info) {
    Info.SetWikiPage("crypt2");
}

NETWORKMODULEDEFS(CCryptMod, t_s("crypt2: AES-256-GCM encrypted channel/private messages"))
