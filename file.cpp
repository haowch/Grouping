
#include "stdafx.h"

#ifndef SIGNATURE
#define SIGNATURE uint
#endif

#ifndef SNORTID
#define SNORTID uint
#endif

typedef std::map<SIGNATURE, std::set<SNORTID>> SIGNATUREMAP;
typedef std::map<SNORTID, std::set<SIGNATURE>> SIDMAP;

struct EDGE
{
	unsigned int Sig;
	unsigned int nSid;
};

struct SigSids
{
	SIGNATURE Sig;
	std::vector<SNORTID> nSids;
};

struct COMPSIGSIDS
{
	BOOL operator()(SigSids &a, SigSids &b)
	{
		return a.nSids.size() > b.nSids.size();
	}
};

void Output(std::vector<SigSids> &result)
{
	struct COMP
	{
		BOOL operator()(SigSids &a, SigSids &b)
		{
			return a.Sig < b.Sig;
		}
	};
	sort(result.begin(), result.end(), COMP());
	std::ofstream fout("C:\\test\\Signatures.txt", std::ios::binary);
	size_t nCnt = result.size();
	fout.write((char*)&nCnt, 4);
	for (std::vector<SigSids>::iterator i = result.begin(); i != result.end(); ++i)
	{
		fout.write((char*)&(i->Sig), 4);
	}
	fout.close();
}

void Output(SIGNATUREMAP &results, std::vector<std::string> &rules)
{
	std::vector<SigSids> result;
	SigSids temp;
	for (SIGNATUREMAP::iterator i = results.begin(); i != results.end(); ++i)
	{
		if ((i->second).size() != 0)
		{
			temp.Sig = i->first;
			for (std::set<SNORTID>::iterator j = (i->second).begin(); j !=(i->second).end(); ++j)
			{
				temp.nSids.push_back(*j);
			}
			result.push_back(temp);
			temp.nSids.clear();
		}
	}

	sort(result.begin(), result.end(), COMPSIGSIDS());
	std::ofstream foutRules("C:\\test\\ResultsWithRules.txt");
	std::string strSid;
	for (std::vector<SigSids>::iterator i = result.begin(); i != result.end(); ++i)
	{
		foutRules << (i->nSids).size() << std::endl;
		for (std::vector<SNORTID>::iterator j = (i->nSids).begin(); j != (i->nSids).end(); ++j)
		{
			std::stringstream ss;
			ss << (*j);
			strSid = "sid:" + ss.str() + ";";
			for (std::vector<std::string>::iterator k = rules.begin(); k !=rules.end(); ++k)
			{
				if (k->find(strSid) != -1)
				{
					foutRules << (*k) << std::endl;
					break;
				}
			}
		}
	}
	foutRules.close();
	std::ofstream foutNoRules("C:\\test\\ResultsWithoutRules.txt");
	for (std::vector<SigSids>::iterator i = result.begin(); i != result.end(); ++i)
	{
		foutNoRules << (i->nSids).size() << std::endl;
	}
	foutNoRules.close();
	Output(result);
}
void OptimizeMapping(SIGNATUREMAP &results, SIDMAP &dmap);
void Optimize(SIGNATUREMAP &gmap, SIGNATUREMAP &results, SIDMAP &dmap)
{
	std::set<SNORTID> Sids;
	for (SIDMAP::iterator i = dmap.begin(); i != dmap.end(); ++i)
	{
		if ((i->second).size() == 1)
		{
			results[*((i->second).begin())].insert(i->first);
			Sids.insert(i->first);
		}
	}
	for (SIGNATUREMAP::iterator i = gmap.begin(); i != gmap.end(); ++i)
	{
		if ((i->second).size() == 1 && !Sids.count(*(i->second.begin())))
		{
			results[i->first].insert(*((i->second).begin()));
			Sids.insert(*((i->second).begin()));
		}
	}
	OptimizeMapping(results, dmap);
}
void OptimizeMapping(SIGNATUREMAP &results, SIDMAP &dmap)
{
	size_t min;
	SIGNATURE sig;
	size_t original_num;
	SIGNATURE original_sig;
	bool flag = true;
	int count = 0;
	size_t second_min;
	SIGNATURE second_sig;
	SIGNATURE third_sig;
	SNORTID Sid;
	bool change;
	while(flag)
	{
		++count;
		std::cout << count << std::endl;
		flag = false;
		for (SIDMAP::iterator i = dmap.begin(); i != dmap.end(); ++i)
		{
			min = dmap.size() + 1;
			original_num = dmap.size() + 1;
			for (std::set<SIGNATURE>::iterator j = (i->second).begin(); j != (i->second).end(); ++j)
			{
				if (min > results[(*j)].size())
				{
					min = results[(*j)].size();
					sig = (*j);
				}
				if (results[(*j)].count(i->first))
				{
					original_num = results[(*j)].size();
					original_sig = (*j);
				}
			}
			if (min + 1 < original_num)
			{
				if (original_num != dmap.size() + 1)
				{
					results[original_sig].erase(i->first);
				}
				results[sig].insert(i->first);
				flag = true;
				//break;
			}
			else if (min + 1 == original_num)
			{
				second_min = min;
				change = false;
				for (std::set<SIGNATURE>::iterator j = (i->second).begin(); j != (i->second).end(); ++j)
				{
					if (min == results[*j].size())
					{
						for (std::set<SNORTID>::iterator k = results[*j].begin(); k != results[*j].end(); ++k)
						{
							for (std::set<SIGNATURE>::iterator l = dmap[*k].begin(); l != dmap[*k].end(); ++l)
							{
								if (results[*l].size() < second_min)
								{
									second_min = results[*l].size();
									second_sig = *j;
									third_sig = *l;
									Sid = *k;
									change = true;
								}
							}
						}
					}
				}
				if (change)
				{
					results[sig].insert(i->first);
					results[original_sig].erase(i->first);
					results[second_sig].erase(Sid);
					results[third_sig].insert(Sid);
					flag = true;
				}
			}
			else
			{
				continue;
			}
		}
	}
}

void ReadRules(std::vector<std::string> &rules)
{
	std::ifstream fin("C:\\test\\AllRules.txt", std::ios::in);
	std::string rule;
	while (std::getline(fin, rule))
	{
		rules.push_back(rule);
	}
}

void Read(std::vector<EDGE> &edges)
{
	std::ifstream fin("C:\\test\\Edges.txt", std::ios::binary);
	size_t nCnt = 0;
	fin.read((char*)&nCnt, 4);
	EDGE edge;
	for (size_t i = 0; i < nCnt; ++i)
	{
		fin.read((char*)&edge.Sig, 4);
		fin.read((char*)&edge.nSid, 4);
		edges.push_back(edge);
	}
}

void main()
{
	std::vector<std::string> rules;

	ReadRules(rules);

	std::cout << "Read Rules complete!" << std::endl;

	std::vector<EDGE> edges;

	Read(edges);

	std::cout << "GenerateEdges complete!" << std::endl;

	SIGNATUREMAP gmap;
	for (std::vector<EDGE>::iterator i = edges.begin(); i != edges.end(); ++i)
	{
		gmap[i->Sig].insert(i->nSid);
	}

	std::cout << "Generate Signature map complete!" << std::endl;
	
	SIDMAP dmap;
	for (std::vector<EDGE>::iterator i = edges.begin(); i != edges.end(); ++i)
	{
		dmap[i->nSid].insert(i->Sig);
	}

	std::cout << "Generate Sid map complete!" << std::endl;

	SIGNATUREMAP results;
	Optimize(gmap, results, dmap);

	std::cout << "Optimize complete!" << std::endl;

	Output(results, rules);

	std::cout << "Output complete!" << std::endl;

	system("pause");
}