using libsvm;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using System.IO;

namespace Filter
{
    class SVMController
    {
        private static Dictionary<int, string> _predictionDictionary = new Dictionary<int, string> { { -1, "SqlInjection" }, { 1, "SafeRequest" } };
        private double accuracy;

        // Uczenie algorytmu
        public void Train()
        {
            // Pobieranie pobieranie danych z zestawów do trenowanie algorytmu znajduje się w konstruktorze klasy SVMDataManager ->
            SVMDataManager data = new SVMDataManager();

            // Tworzenie macierzy (wraz z wektorami)
            var problemBuilder = new SVMProblemBuilder();
            var problem = problemBuilder.CreateMatrix(data.RequestText, data.ClassValue, data.Vocabulary.ToList());

            const double C = 0.5;
            C_SVC model = new C_SVC(problem, KernelHelper.LinearKernel(), C);
            accuracy = model.GetCrossValidationAccuracy(100);

            // Export modelu oraz słownika 
            model.Export(string.Format(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, string.Format(@"WAF\model_{0}_accuracy.model", accuracy))));
            System.IO.File.WriteAllLines(string.Format(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, string.Format(@"WAF\model_{0}_vocabulary.txt", accuracy))), data.Vocabulary);

        }

        // Funkcja klasyfikująca
        public bool Classyfi(string request)
        {
            SVMDataManager data = new SVMDataManager();
            C_SVC model = new C_SVC(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, @"WAF\model.model"));

            // Buduje wektor na podstawie wprowadzonego tekstu 
            var newX = SVMProblemBuilder.CreateVector(SVMDataManager.SeparateNonAlphanumeric(request), data.Vocabulary);
            //var predictedYProb = model.PredictProbabilities(newX);

            // Start analizy czasu na potrzeby testów
            //Stopwatch stopWatch = new Stopwatch();
            //stopWatch.Start();

            // Klasyfikacja nowo utworzonego wektora na podstawie modelu
            var predictedY = model.Predict(newX);

            // Logowanie czasu na potrzeby testów
            //File.WriteAllText(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, @"WAF\log.txt"), string.Format("The prediction is {0}. Time is {1}.", _predictionDictionary[(int)predictedY], stopWatch.ElapsedMilliseconds));

            // Zwracanie wyniku
            if (predictedY == -1)
            {
                return false;

            } else
            {
                return true;
            }
            
        }

    }
}
