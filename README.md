# Babelfish TDS Prelogin Packet Demo

This example demonstrates the byte-level structure of a simplified TDS (Tabular Data Stream) Pre-Login packet, which is the initial communication phase before authentication. It illustrates the complexity of the protocol where vulnerabilities like pre-authentication Remote Code Execution (RCE) discussed in the article can arise due to malformed packet parsing. The script attempts to send this packet to a hypothetical Babelfish (or SQL Server) instance.

## Language

`python`

## How to Run

1. Save the code as `main.py`.
2. Run from your terminal: `python main.py`
3. (Optional) To see a successful connection and response, ensure a Babelfish or SQL Server instance is running and accessible on `127.0.0.1:1433` (or modify `TARGET_HOST`/`TARGET_PORT` in the script).

## Original Article

This example accompanies the Turkish article: [Babelfish TDS Zafiyetleri: Kimlik Doğrulama Öncesi Uzaktan Kod Çalıştırma (RCE) Yoluna Karşı Pratik Bir Yama Planı](https://fatihsoysal.com/blog/babelfish-tds-zafiyetleri-kimlik-dogrulama-oncesi-uzaktan-kod-calistirma-rce-yoluna-karsi-pratik-bir-yama-plani/).

## License

MIT — see [LICENSE](LICENSE).
