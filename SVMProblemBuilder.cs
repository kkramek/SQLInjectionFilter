using libsvm;
using System;
using System.Collections.Generic;
using System.Linq;

namespace Filter
{
    public class SVMProblemBuilder
    {
        // Buduje obiekt który jest reprezentacją macierzy algorytmu SVM.
        public svm_problem CreateMatrix(IEnumerable<string> x, double[] y, IReadOnlyList<string> vocabulary)
        {
            return new svm_problem
            {
                y = y,
                x = x.Select(vector => CreateVector(vector, vocabulary)).ToArray(),
                l = y.Length
            };
        }

        // Buduje wektor składający się z indeksu danego słowa w słowniku oraz ilości jego wystąpień.
        public static svm_node[] CreateVector(string x, IReadOnlyList<string> vocabulary)
        {
            var svmNodeList = new List<svm_node>(vocabulary.Count);
            string[] words = x.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);

            for (int i = 0; i < vocabulary.Count; i++)
            {
                int occurenceNumber = words.Count(s => String.Equals(s, vocabulary[i], StringComparison.OrdinalIgnoreCase));

                if (occurenceNumber == 0)
                {
                    continue;
                }

                svmNodeList.Add(new svm_node
                {
                    index = i + 1,
                    value = occurenceNumber
                });

            }

            return svmNodeList.ToArray();

        }

    }
}
