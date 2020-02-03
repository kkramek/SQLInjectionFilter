using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Web;

namespace Filter
{
    class AnalyzerHandler
    {
        string[] skipParams = { "__RequestVerificationToken", "ReturnUrl" };

        private HttpRequest request;

        public AnalyzerHandler(HttpRequest request)
        {
            this.request = request;
        }

        // Tu następuje analiza danych ->
        public AnalyzedRequest IsRequestSafe()
        {
            AnalyzedRequest result = new AnalyzedRequest();
            result.IsRequestSafe = true;

            SVMController svm = new SVMController();

            // Sprawdzenie typu oraz ilości parametrów
            if (request.RequestType == "GET" && request.QueryString.Count > 0)
            {
                foreach (string key in request.QueryString.Keys)
                {
                    // !skipParams.Contains(key) - Zostało dodane w celu wyeliminowania analizy pustych requestów podtrzymania sesji.
                    // svm.Classyfi -> Tu następuje klasyfikacja czy parametr jest niebezpieczny czy też nie.
                    if (!skipParams.Contains(key) && !svm.Classyfi(request.QueryString.Get(key)))
                    {
                        result.SuspiciousValues += " " + request.QueryString.Get(key);
                        result.IsRequestSafe = false;
                    }
                }

            }  // Sprawdzenie typu oraz ilości parametrów
            else if (request.RequestType == "POST" && request.Form.Count > 0)
            {
                foreach (string key in request.Form.Keys)
                {
                    // !skipParams.Contains(key) - Zostało dodane w celu wyeliminowania analizy pustych requestów podtrzymania sesji.
                    // svm.Classyfi -> Tu następuje klasyfikacja czy parametr jest niebezpieczny czy też nie.
                    if (!skipParams.Contains(key) && !svm.Classyfi(request.Form[key]))
                    {
                        result.SuspiciousValues += " " + request.Form[key];
                        result.IsRequestSafe = false;
                    }
                }
            }

            return result;
        }


        public HttpRequest Request
        {
            get => request;
            set => request = value;
        }

    }
}
