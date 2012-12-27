
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
	SIGNATURE Sig;
	SNORTID nSid;
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
	//std::ofstream fout("C:\\test\\Signatures.txt");
	//for (std::vector<SigSids>::iterator i = result.begin(); i != result.end(); ++i)
	//{
	//	fout << i->Sig << std::endl;
	//}
	//fout.close();
}

unsigned int Hash(SIGNATURE &value)
{
	return value % 39953;
	//return value % 15991; //0.3%
	//return value % 34981; //0%
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
	std::ofstream foutNoRules("C:\\test\\ResultsWithoutRules.txt");
	std::map<unsigned int, std::set<SIGNATURE>> tmp;
	struct COMP
	{
		BOOL operator()(SigSids &a, SigSids &b)
		{
			return a.Sig < b.Sig;
		}
	};
	sort(result.begin(), result.end(), COMP());
	for (std::vector<SigSids>::iterator i = result.begin(); i != result.end(); ++i)
	{
		tmp[Hash(i->Sig)].insert(i->Sig);
		//for (size_t j = 0; j < 4; ++j)
		//{
		//	foutNoRules << ((unsigned char*)&(i->Sig))[j];
		//}
		//foutNoRules << "\t";
		//foutNoRules << i->nSids.size() << "\t";
		foutNoRules << i->Sig << "\t" << i->nSids.size() << "\t";
		for (std::vector<SNORTID>::iterator j = i->nSids.begin(); j != i->nSids.end(); ++j)
		{
			foutNoRules << *j << " ";
		}
		foutNoRules << "\t" << Hash(i->Sig) << std::endl;
	}
	foutNoRules.close();
	size_t count = 0;
	for (std::map<unsigned int, std::set<SIGNATURE>>::iterator i = tmp.begin(); i != tmp.end(); ++i)
	{
		if (i->second.size() > 1)
		{
			count += i->second.size() - 1;
			std::cout << i->first << std::endl;
		}
	}
	std::cout << "Number of Signatures that have conflict with others:" << count << std::endl;
	std::cout << "Total number of Signatures:" << result.size() << std::endl;
	std::cout << "Conflict rate:" << count / (result.size() + 0.0) * 100 << "%" << std::endl;
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

typedef std::set<SIGNATURE> SIGSET;
struct AdjustPath
{
	SIGNATURE parent;
	SIGNATURE self;
	size_t level;
};
bool myFindAdjust(std::map<unsigned int, SIGSET> &mapHashSigSet, SIDMAP &sidMap, SIGNATUREMAP &results, std::vector<SIGNATURE> &SigSet, size_t nDepth, std::vector<AdjustPath> &vecPath, size_t count);

void Adjust(SIGNATUREMAP &results, SIDMAP &dmap)
{
	std::map<unsigned int, SIGSET> mapHashSigSet;
	for (SIGNATUREMAP::iterator i = results.begin(); i != results.end(); ++i)
	{
		if (i->second.size() >= 1)
		{
			mapHashSigSet[Hash((SIGNATURE)i->first)].insert(i->first);
		}
	}
	int count = 0;
	bool flag = true;
	while (flag)
	{
		++count;
		std::cout << "First Adjust: " << count << std::endl;
		flag = false;
		for (SIGNATUREMAP::iterator i = results.begin(); i != results.end(); ++i)
		{
			unsigned int iHashValue = Hash((SIGNATURE)i->first);
			SIGSET &iset = mapHashSigSet[iHashValue];
			size_t count = iset.size();
			if (i->second.size() == 1 && count >= 2)
			{
				for (std::set<SNORTID>::iterator j = i->second.begin(); j != i->second.end();)
				{
					std::set<SIGNATURE>::iterator k = dmap[*j].begin();
					for (; k != dmap[*j].end(); ++k)
					{
						unsigned int kHashValue = Hash((SIGNATURE)(*k));
						SIGSET &kset = mapHashSigSet[kHashValue];
						if (results[*k].size() == 0 && kset.size() + 1 < count)
						{
							kset.insert(*k);
							iset.erase(i->first);
							results[*k].insert(*j);
							flag = true;
							break;
						}
					}
					if (k == dmap[*j].end())
					{
						break;
					}
					else
					{
						j = i->second.erase(j);
					}
				}
			}
		}
	}
	count = 0;
	flag = true;
	while (flag)
	{
		++count;
		std::cout << "Second Adjust: " << count << std::endl;
		flag = false;
		for (SIGNATUREMAP::iterator i = results.begin(); i != results.end(); ++i)
		{
			unsigned int iHashValue = Hash((SIGNATURE)i->first);
			SIGSET &iset = mapHashSigSet[iHashValue];
			size_t count = iset.size();
			if (i->second.size() == 1 && count >= 2)
			{
				std::vector<SIGNATURE> Sigs;
				std::vector<AdjustPath> vecPath;
				SIGNATURE oneSig;
				oneSig = i->first;
				Sigs.push_back(oneSig);
				if (myFindAdjust(mapHashSigSet, dmap, results, Sigs, 1, vecPath, count))
				{
					flag = true;
					AdjustPath onePoint;
					onePoint.parent = vecPath[vecPath.size() - 1].parent;
					onePoint.self = vecPath[vecPath.size() - 1].self;
					onePoint.level = vecPath[vecPath.size() - 1].level;
					SNORTID oneSid;
					while (onePoint.level != 0)
					{
						oneSid = *(results[onePoint.parent].begin());
						results[onePoint.self].insert(oneSid);
						results[onePoint.parent].erase(oneSid);
						for (std::vector<AdjustPath>::iterator j = vecPath.begin(); j != vecPath.end(); ++j)
						{
							if (j->level + 1 == onePoint.level && j->self == onePoint.parent)
							{
								onePoint.parent = j->parent;
								onePoint.self = j->self;
								onePoint.level = j->level;
								break;
							}
						}
					}
					oneSid = *(results[onePoint.parent].begin());
					results[onePoint.self].insert(oneSid);
					results[onePoint.parent].erase(oneSid);
				}
				vecPath.clear();
			}
		}
	}
}

bool myFindAdjust(std::map<unsigned int, SIGSET> &mapHashSigSet, SIDMAP &sidMap, SIGNATUREMAP &results, std::vector<SIGNATURE> &Sigs, size_t nDepth, std::vector<AdjustPath> &vecPath, size_t count)
{
	if (nDepth > 10 || Sigs.empty())
	{
		return false;
	}
	std::vector<SIGNATURE> nextSigs;
	AdjustPath onePoint;
	if (vecPath.size() == 0)
	{
		onePoint.level = 0;
	}
	else
	{
		onePoint.level = vecPath[vecPath.size() - 1].level + 1;
	}
	for (std::vector<SIGNATURE>::iterator i = Sigs.begin(); i != Sigs.end(); ++i)
	{
		onePoint.parent = *i;
		SNORTID sid = *(results[*i].begin());
		for (std::set<SIGNATURE>::iterator k = sidMap[sid].begin(); k != sidMap[sid].end(); ++k)
		{
			SIGSET &kset = mapHashSigSet[Hash((SIGNATURE)(*k))];
			if (kset.size() + 1 < count && results[*k].size() == 0)
			{
				onePoint.self = *k;
				vecPath.push_back(onePoint);
				return true;
			}
			if (kset.size() + 1 == count && results[*k].size() == 1)
			{
				nextSigs.push_back(*k);
				onePoint.self = *k;
				vecPath.push_back(onePoint);
			}
		}
	}
	Sigs.clear();

	return myFindAdjust(mapHashSigSet, sidMap, results, nextSigs, nDepth + 1, vecPath, count);
}

//void Adjust(SIGNATUREMAP &results, SIDMAP &dmap)
//{
//	std::set<unsigned int> tmp;
//	std::set<SIGNATURE>::iterator k;
//	bool flag = true;
//	for (SIGNATUREMAP::iterator i = results.begin(); i != results.end(); ++i)
//	{
//		if (i->second.size() > 1)
//		{
//			tmp.insert(Hash((unsigned int)i->first));
//		}
//	}
//	while (flag)
//	{
//		flag = false;
//		for (SIGNATUREMAP::iterator i = results.begin(); i != results.end(); ++i)
//		{
//			if (i->second.size() == 1)
//			{
//				if (tmp.count(Hash((unsigned int)i->first)))
//				{
//					for (std::set<SNORTID>::iterator j = i->second.begin(); j != i->second.end();)
//					{
//						for (k = dmap[*j].begin(); k != dmap[*j].end(); ++k)
//						{
//							if (!tmp.count(Hash((unsigned int)(*k))) && results[*k].size() == 0)
//							{
//								tmp.insert(Hash((unsigned int)(*k)));
//								results[*k].insert(*j);
//								flag = true;
//								break;
//							}
//						}
//						if (k == dmap[*j].end())
//						{
//							break;
//						}
//						else
//						{
//							j = i->second.erase(j);
//						}
//					}
//				}
//				else
//				{
//					tmp.insert(Hash((unsigned int)i->first));
//				}
//			}
//		}
//	}
//}
struct OptimizePath
{
	SIGNATURE original_Sig;
	SNORTID Sid;
	SIGNATURE current_Sig;
	size_t level;
};
bool myFindOptimize(SIGNATUREMAP &results, SIDMAP &dmap, std::vector<SIGNATURE> Sids, size_t count, std::vector<OptimizePath> &vecPath, size_t nDepth);

void OptimizeMapping(SIGNATUREMAP &results, SIDMAP &dmap)
{
	size_t min;
	SIGNATURE sig;
	size_t original_num;
	SIGNATURE original_sig;
	bool flag = true;
	int count = 0;
	while(flag)
	{
		++count;
		std::cout << "First Optimize: " << count << std::endl;
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
			if (original_num >= 2 && min + 1 < original_num)
			{
				if (original_num != dmap.size() + 1)
				{
					results[original_sig].erase(i->first);
				}
				results[sig].insert(i->first);
				flag = true;
				//break;
			}
		}
	}
	flag = true;
	count = 0;
	while (flag)
	{
		++count;
		std::cout << "Second Optimize: " << count << std::endl;
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
			if (original_num >= 2 && min + 1 == original_num)
			{
				std::vector<SIGNATURE> Sigs;
				std::vector<OptimizePath> vecPath;
				OptimizePath onePoint;
				onePoint.level = 0;
				onePoint.Sid = i->first;
				onePoint.original_Sig = original_sig;
				for (std::set<SIGNATURE>::iterator j = (i->second).begin(); j != (i->second).end(); ++j)
				{
					if (min == results[*j].size())
					{
						onePoint.current_Sig = *j;
						vecPath.push_back(onePoint);
						Sigs.push_back(*j);
					}
				}
				if (myFindOptimize(results, dmap, Sigs, min, vecPath, 1))
				{
					flag = true;
					OptimizePath onePoint;
					onePoint.original_Sig = vecPath[vecPath.size() - 1].original_Sig;
					onePoint.Sid = vecPath[vecPath.size() - 1].Sid;
					onePoint.current_Sig = vecPath[vecPath.size() - 1].current_Sig;
					onePoint.level = vecPath[vecPath.size() - 1].level;
					while (onePoint.level != 0)
					{
						results[onePoint.original_Sig].erase(onePoint.Sid);
						results[onePoint.current_Sig].insert(onePoint.Sid);
						for (std::vector<OptimizePath>::iterator j = vecPath.begin(); j != vecPath.end(); ++j)
						{
							if (j->level + 1 == onePoint.level && j->current_Sig == onePoint.original_Sig)
							{
								onePoint.original_Sig = j->original_Sig;
								onePoint.Sid = j->Sid;
								onePoint.current_Sig = j->current_Sig;
								onePoint.level = j->level;
								break;
							}
						}
					}
					results[onePoint.original_Sig].erase(onePoint.Sid);
					results[onePoint.current_Sig].insert(onePoint.Sid);
				}
			}
		}
	}
}

bool myFindOptimize(SIGNATUREMAP &results, SIDMAP &dmap, std::vector<SIGNATURE> Sigs, size_t count, std::vector<OptimizePath> &vecPath, size_t nDepth)
{
	if (nDepth > 1 || Sigs.empty())
	{
		return false;
	}
	OptimizePath onePoint;
	if (vecPath.size() == 0)
	{
		onePoint.level = 0;
	}
	else
	{
		onePoint.level = vecPath[vecPath.size() - 1].level + 1;
	}
	std::vector<SIGNATURE> nextSigs;
	for (std::vector<SIGNATURE>::iterator i = Sigs.begin(); i != Sigs.end(); ++i)
	{
		onePoint.original_Sig = *i;
		for (std::set<SNORTID>::iterator j = results[*i].begin(); j != results[*i].end(); ++j)
		{
			onePoint.Sid = *j;
			for (std::set<SIGNATURE>::iterator k = dmap[*j].begin(); k != dmap[*j].end(); ++k)
			{
				if (results[*k].size() < count)
				{
					onePoint.current_Sig = *k;
					vecPath.push_back(onePoint);
					return true;
				}
				else if (results[*k].size() == count && *k != *i)
				{
					nextSigs.push_back(*k);
					onePoint.current_Sig = *k;
					vecPath.push_back(onePoint);
				}
				else
				{
					continue;
				}
			}
		}
	}
	return myFindOptimize(results, dmap, nextSigs, count, vecPath, nDepth + 1);
}

//void OptimizeMapping(SIGNATUREMAP &results, SIDMAP &dmap)
//{
//	size_t min;
//	SIGNATURE sig;
//	size_t original_num;
//	SIGNATURE original_sig;
//	bool flag = true;
//	int count = 0;
//	size_t second_min;
//	SIGNATURE second_sig;
//	SIGNATURE third_sig;
//	SNORTID Sid;
//	bool change;
//	while(flag)
//	{
//		++count;
//		std::cout << count << std::endl;
//		flag = false;
//		for (SIDMAP::iterator i = dmap.begin(); i != dmap.end(); ++i)
//		{
//			min = dmap.size() + 1;
//			original_num = dmap.size() + 1;
//			for (std::set<SIGNATURE>::iterator j = (i->second).begin(); j != (i->second).end(); ++j)
//			{
//				if (min > results[(*j)].size())
//				{
//					min = results[(*j)].size();
//					sig = (*j);
//				}
//				if (results[(*j)].count(i->first))
//				{
//					original_num = results[(*j)].size();
//					original_sig = (*j);
//				}
//			}
//			if (original_num >= 2 && min + 1 < original_num)
//			{
//				if (original_num != dmap.size() + 1)
//				{
//					results[original_sig].erase(i->first);
//				}
//				results[sig].insert(i->first);
//				flag = true;
//				//break;
//			}
//			else if (original_num >= 2 && min + 1 == original_num)
//			{
//				second_min = min;
//				change = false;
//				for (std::set<SIGNATURE>::iterator j = (i->second).begin(); j != (i->second).end(); ++j)
//				{
//					if (min == results[*j].size())
//					{
//						for (std::set<SNORTID>::iterator k = results[*j].begin(); k != results[*j].end(); ++k)
//						{
//							for (std::set<SIGNATURE>::iterator l = dmap[*k].begin(); l != dmap[*k].end(); ++l)
//							{
//								if (results[*l].size() < second_min)
//								{
//									second_min = results[*l].size();
//									second_sig = *j;
//									third_sig = *l;
//									Sid = *k;
//									change = true;
//								}
//							}
//						}
//					}
//				}
//				if (change)
//				{
//					results[sig].insert(i->first);
//					results[original_sig].erase(i->first);
//					results[second_sig].erase(Sid);
//					results[third_sig].insert(Sid);
//					flag = true;
//				}
//			}
//			else
//			{
//				continue;
//			}
//		}
//	}
//}

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

	Adjust(results, dmap);

	std::cout << "Adjust complete!" << std::endl;

	Output(results, rules);

	std::cout << "Output complete!" << std::endl;

	system("pause");
}