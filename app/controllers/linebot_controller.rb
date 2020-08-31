class LinebotController < ApplicationController
  # line-botの利用を許可
  require 'line/bot'
  # callbackアクションのCSRF対策の設定を無効化
  # なぜ無効化の設定が必要なの？
  # webhookを利用するからCSRF対策を無効化

  # webhookとは
  # Webアプリケーション同士が連携するときの考え方の一つ、 Webアプリケーションでイベントが実行された際、外部サービスにHTTPで通知する仕組み
  # 今回の場合だと、友だち追加やメッセージの送信のようなイベントが発生すると、LINEプラットフォームからWebhook URL（ボットサーバー）にHTTPS POSTリクエストが送信される

  # CSRF(クロスサイト・リクエストフォージェリ)対策
  # webアプリケーションの脆弱性をついた攻撃、
  # 利用サービスにログインした状態で攻撃用の罠がはってあるサイトを閲覧することで、ログイン情報を利用され、意図しないリクエストを送信してしまう

  # railsはデフォルトで意図しないリクエストを送信しないようにCSRF対策が施されているため、webhookで連携できないから、必要なアクションだけ覗いている
  protect_from_forgery :except => [:callback]

  def client
    # a ||= xxx とした時、||= の意味はa が 偽 か 未定義 なら a に xxx を代入する
    # Line::Bot::Clientのインスタンスを作成
    @client ||= Line::Bot::Client.new { |config|
      config.channel_secret = ENV["LINE_CHANNEL_SECRET"]
      config.channel_token = ENV["LINE_CHANNEL_TOKEN"]
    }
  end

  def callback
    # JSONでPOSTリクエストを受けた際に、受け渡されるパラメーターを読み込み代入している
    body = request.body.read
    # リクエストがLINEプラットフォームから送られたことを確認するために、ボットサーバーでリクエストヘッダーのX-Line-Signatureに含まれる署名を検証
    signature = request.env['HTTP_X_LINE_SIGNATURE']
    unless client.validate_signature(body, signature)
      head :bad_request
    end

    events = client.parse_events_from(body)

    events.each { |event|
      case event
      when Line::Bot::Event::Message
        case event.type
        when Line::Bot::Event::MessageType::Text
          # LINEから送られてきたメッセージが「アンケート」と一致するかチェック
          if event.message['text'].eql?('アンケート')
            # private内のtemplateメソッドを呼び出します。
            # replyTokenはイベントへの応答に使用するトークン
            client.reply_message(event['replyToken'], template)
          end
        end
      end
    }

    head :ok
  end

  private

  def template
    {
      "type": "template",
      "altText": "this is a confirm template",
      "template": {
          "type": "confirm",
          "text": "今日のもくもく会は楽しいですか？",
          "actions": [
              {
                "type": "message",
                # Botから送られてきたメッセージに表示される文字列です。
                "label": "楽しい",
                # ボタンを押した時にBotに送られる文字列です。
                "text": "楽しい"
              },
              {
                "type": "message",
                "label": "楽しくない",
                "text": "楽しくない"
              }
          ]
      }
    }
  end
end
