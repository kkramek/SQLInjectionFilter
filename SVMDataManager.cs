using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Filter
{
    public class SVMDataManager
    {
        private string negativeDataSetPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, @"WAF\NegativeDataSet.txt");
        private string positiveDataSetPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, @"WAF\PositiveDataSet.txt");

        private List<string> requestText;
        private double[] classValue;
        private List<string> vocabulary;

        public List<string> RequestText
        {
            get { return requestText; }
            set { requestText = value; }
        }
        public double[] ClassValue
        {
            get { return classValue; }
            set { classValue = value; }
        }

        public List<string> Vocabulary
        {
            get { return vocabulary; }
            set { vocabulary = value; }
        }

        // Tu odbywa się wczytywanie danych z sestawów treningowych.
        public SVMDataManager()
        {
            int negativeRowNumber;
            int positiveRowNumber;

            // Wczytywanie zestawu SQL Injection
            this.requestText = ReadDataSetFromFile(this.negativeDataSetPath).ToList();
            negativeRowNumber = this.requestText.Count;

            // Wczytywanie zestawu zwykłych treści uznanych za dopuszczalne.
            this.requestText.AddRange(ReadDataSetFromFile(this.positiveDataSetPath));
            positiveRowNumber = this.requestText.Count - negativeRowNumber;

            // Ustawianie klas. (Budowanie listy klas, gdzie każdy wiersz słownika ma swoją klasę na liście klas. (Przez klasę rozumie się -1 SqlInjection, 1 NormalRequest) )
            SetClassValues(negativeRowNumber, positiveRowNumber);

            // Wczytywanie połączonych zestawów do jednego, wspólnego słownika.
            this.vocabulary = requestText.SelectMany(GetWords).Distinct().OrderBy(word => word).ToList();

        }

        // Buduje liste klasyfikacji odpowiadających jej wierzy w słowniku.
        public void SetClassValues(int negativeRowNumber, int positiveRowNumber)
        {
            this.classValue = new double[negativeRowNumber + positiveRowNumber];


            for (int i = 0; i < negativeRowNumber + 1; ++i)
            {
                this.classValue[i] = -1;
            }

            for (int i = negativeRowNumber + 1; i < negativeRowNumber + positiveRowNumber; ++i)
            {
                this.classValue[i] = 1;
            }

        }

        // Wczytywanie z pliku
        public IEnumerable<String> ReadDataSetFromFile(string path)
        {
            return File.ReadLines(path);
        }

        // Pobieranie słów z wiersza
        private static IEnumerable<string> GetWords(string requestText)
        {
            string result = SeparateNonAlphanumeric(requestText);//requestText; //
            return result.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
        }

        // Oddzielanie od siebie znaków nie alfanumerycznych i traktowanie ich jako osobne wyrazy. (Tak by np "1 = 1" było jednoznaczne z "1=1")
        public static string SeparateNonAlphanumeric(string line)
        {
            string result = "";

            for (int i = 0; i < line.Length; i++)
            {
                if (Char.IsLetter(line[i]))
                {
                    result += line[i];
                }
                else
                {
                    result += ' ';
                    result += line[i];
                }

            }

            return result;
        }
    }
}
