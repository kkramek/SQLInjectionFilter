// Class Library .NET Framework
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using System.Web;

namespace Filter
{
    class WafModule : IHttpModule
    {
        public delegate void WafEventHandler(Object s, EventArgs e);
        private WafEventHandler _wafEventHandler = null;
        static private HttpApplication _application;

        public static HttpApplication Application { get => _application; set => _application = value; }

        public void Dispose()
        {
            throw new NotImplementedException();
        }

        // Inicjalizacja modułu. 
        public void Init(HttpApplication app)
        {
            //Podpięcie eventu oraz wybranie momentu, w którym ma zostać odpalony. W tym przypadku zaraz na początku przetwarzania zapytania.
            Application = app;
            app.BeginRequest += new EventHandler(OnBeginRequest);
        }

        // Event
        public void OnBeginRequest(Object sender, EventArgs e)
        {
            // Autorskie zabezpieczenie przed zapętlaniem się requestów. Bez niego czasem dochodziło do nieskończonego zapętlania się zapytań co skutkowało timeoutem i uniemożliwiało korzystanie z aplikacji.
            // Zabezpieczenie polega na doklejeniu do requesta własnego nagłówka "X-Waf-Header". Requesty zawierające ten nagłówek są od razu ubijane. 
            if (HttpContext.Current.Request.Headers.Get("X-Waf-Header") != null)
            {
                return;
            }

            // Sprawdzenie poprawności danych.
            if(sender != null && sender is HttpApplication)
            {
                // Pobranie danych zapytania w postaci obiektu.
                var request = ((HttpApplication)sender).Context.Request;
                AnalyzerHandler analyzer = new AnalyzerHandler(request);

                // Tu następuje analiza danych ->
                AnalyzedRequest analyzedRequest = analyzer.IsRequestSafe();

                if (analyzedRequest.IsRequestSafe)
                {
                    //StreamWriter sw = File.AppendText(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, @"WAF\log.txt"));
                    //sw.WriteLine(string.Format("{0} [SAFE REQUEST] \t From IP: {1} \t Text: {2}", DateTime.Now.ToString(), GetIP(), analyzedRequest.SafeValues));
                    //sw.Close();
                }
                else
                {
                    // W przypadku sklasyfikowania danych jako atak następuje logowanie danych do pliku tekstowego
                    StreamWriter sw = File.AppendText(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, @"WAF\log.txt"));
                    sw.WriteLine(string.Format("{0} [HACK ATTEMPT] \t From IP: {1} \t Text {2}", DateTime.Now.ToString(), GetIP(), analyzedRequest.SuspiciousValues));
                    sw.Close();
                    // oraz zostaje wysłana odpowiedź z błędem serwera HTTP 451 i komunikatem że wykryto atak. 
                    throw new HttpException(451, "SQL Injection Detected!!!");
                }


            }

            // Ustawienie nagłówka zabezpieczającego przed zapętleniem
            HttpContext context = HttpContext.Current;
            context.Request.Headers.Add("X-Waf-Header", "true");

            // W przypadku zapytań typu POST występował problem z analizą danych. Każda próba odczytu danych z formularza wstrzymywała potok przetwarzania requestu.
            if (context.Request.HttpMethod.ToLower() == "post")
            {
                // W związku z powyższym w tym miejscu następuje wznowienie przesyłu requestu do aplikacji.
                context.Server.TransferRequest(context.Request.Path, true, context.Request.HttpMethod, context.Request.Headers);
            }
        }

        public event WafEventHandler WafEvent
        {
            add { _wafEventHandler += value; }
            remove { _wafEventHandler -= value; }
        }

        // Pobieranie adresu IP na potrzeby logowania
        public static String GetIP()
        {
            String ip = HttpContext.Current.Request.ServerVariables["HTTP_X_FORWARDED_FOR"];

            if (string.IsNullOrEmpty(ip))
            {
                ip = HttpContext.Current.Request.ServerVariables["REMOTE_ADDR"];
            }

            return ip;
        }

    }

}
